package agent

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/common"
	wasmEngine "github.com/OpenNHP/opennhp/nhp/core/wasm/engine"
	_ "github.com/OpenNHP/opennhp/nhp/log"
	utils "github.com/OpenNHP/opennhp/nhp/utils"
)

var (
	routes = struct {
		sync.RWMutex
		m map[string]map[string]gin.HandlerFunc // method -> path -> handler
	}{m: make(map[string]map[string]gin.HandlerFunc)}

	serviceApiPrefix = "/api/v1"

	taSuffix = ".ta"
)

func (a *UdpAgent) CheckAgentSafeOrNot(targetPaths ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		for _, target := range targetPaths {
			if strings.HasPrefix(path, target) {
				if !a.safeTee.Load() {
					c.JSON(http.StatusForbidden, gin.H{"error": "TEE in which is Agent is not safe"})
					c.Abort()
					return
				}
			}
		}
	}
}

func (a *UdpAgent) CreateDHPWebConsole() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.Use(a.CheckAgentSafeOrNot(taApiPrefix))

	router.GET("/", func(c *gin.Context) {
		c.File(filepath.Join(common.ExeDirPath, "etc", "www", "index.html"))
	})

	router.POST(fmt.Sprintf("%s/%s", serviceApiPrefix, "config/server"), a.configServer)
	router.GET(fmt.Sprintf("%s/%s", serviceApiPrefix, "config/server"), a.getServerConfig)

	router.GET(fmt.Sprintf("%s/%s", serviceApiPrefix, "key/agent"), a.getAgentPublicKey)
	router.GET(fmt.Sprintf("%s/%s", serviceApiPrefix, "key/tee"), a.getTeePublicKey)
	router.POST(fmt.Sprintf("%s/%s", serviceApiPrefix, "key/agent/rotate"), a.rotateAgentKey)
	router.POST(fmt.Sprintf("%s/%s", serviceApiPrefix, "key/tee/rotate"), a.rotateTeeKey)

	router.GET(fmt.Sprintf("%s/%s", serviceApiPrefix, "agent/restart"), a.restartAgent)

	router.GET(fmt.Sprintf("%s/%s", serviceApiPrefix, "status/agent"), a.getTeeStatus)

	router.GET(fmt.Sprintf("%s/%s", serviceApiPrefix, "attestation/tee"), a.getTeeAttestation)

	router.POST(fmt.Sprintf("%s/%s", taApiPrefix, "register"), a.registerTAService)

	// Dynamic route handler - this catches all requests and checks our dynamic routes
	router.NoRoute(func(c *gin.Context) {
		method := c.Request.Method
		path := c.Request.URL.Path

		routes.RLock()
		defer routes.RUnlock()

		// Check if we have a handler for this method and path
		if methodRoutes, ok := routes.m[method]; ok {
			if handler, ok := methodRoutes[path]; ok {
				handler(c)
				return
			}
		}

		// If no dynamic route found, return 404
		c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
	})

	go func() {
		if err := router.RunTLS(
			":443", filepath.Join(common.ExeDirPath, "server.crt"), filepath.Join(common.ExeDirPath, "server.key"),
		); err != nil {
			panic(err)
		}
	}()
}

func (a *UdpAgent) registerTAService(c *gin.Context) {
	description := c.PostForm("description")
	taName := c.PostForm("name")

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	taDir := filepath.Join(ExeDirPath, "etc", "ta")
	if err := os.MkdirAll(taDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	fileUuid, err := utils.GenerateUUIDv4()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	fullFilePath := filepath.Join(taDir, fileUuid+taSuffix)
	if err := c.SaveUploadedFile(file, fullFilePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := os.Chmod(fullFilePath, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// calculate the md5sum of the file
	md5sum, err := utils.Md5sum(fullFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_, err = os.Stat(filepath.Join(taDir, md5sum))
	if err == nil { // corresponding trusted application has been uploaded.
		os.Remove(fullFilePath)

		fileInfo, err := utils.LoadJsonFileAsStruct(filepath.Join(taDir, md5sum))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		fileUuid = fileInfo.(map[string]any)["uuid"].(string)
	}

	// save file information into the file which name is md5sum, no matter the file exists or not.
	utils.SaveStructAsJsonFile(filepath.Join(taDir, md5sum), map[string]any{
		"fileName":    file.Filename,
		"name":        taName,
		"uuid":        fileUuid,
		"size":        file.Size,
		"description": description,
	})

	ta, err := NewTrustApplication(filepath.Join(taDir, fileUuid+taSuffix))
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
	}

	a.addTARoute(ta)

	c.JSON(http.StatusOK, ta.GetSupportedFunctions())
}

func (a *UdpAgent) addTARoute(ta *TrustedApplication) {
	routes.Lock()
	for _, function := range ta.Functions {
		if _, exists := routes.m[function.Method]; !exists {
			routes.m[function.Method] = make(map[string]gin.HandlerFunc)
		}

		if _, exists := routes.m[function.Method][function.Name]; !exists {
			routes.m[function.Method][function.Name] = a.callFunction
		}
	}
	routes.Unlock()
}

func (a *UdpAgent) callFunction(c *gin.Context) {
	path := c.Request.URL.Path

	var body map[string]any

	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if _, exist := body["doId"]; !exist {
		c.JSON(http.StatusBadRequest, gin.H{"error": "doId is missing"})
		return
	}

	parts := strings.Split(path, "/")

	// url example: /api/v1/ta/<taId>/<function>
	function := parts[len(parts)-1]
	taId := parts[len(parts)-2]

	taDir := filepath.Join(ExeDirPath, "etc", "ta")
	fullTaPath := filepath.Join(taDir, taId+taSuffix)

	ccRes, err := a.StartConfidentialComputing(body["doId"].(string), fullTaPath, function, body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ccRes)
}

func (a *UdpAgent) getAgentPublicKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"publicKey": a.config.GetAgentEcdh().PublicKeyBase64()})
}

func (a *UdpAgent) getTeePublicKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"publicKey": a.config.GetTeeEcdh().PublicKeyBase64()})
}

func (a *UdpAgent) configServer(c *gin.Context) {
	var peers Peers

	if err := c.BindJSON(&peers); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fileName := filepath.Join(ExeDirPath, "etc", "server.toml")

	file, err := os.Create(fileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer file.Close()

	encoder := toml.NewEncoder(file)
	if err := encoder.Encode(peers); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "successfully configure nhp server info in agent"})
}

func (a *UdpAgent) getServerConfig(c *gin.Context) {
	var peers Peers

	fileName := filepath.Join(ExeDirPath, "etc", "server.toml")
	content, err := os.ReadFile(fileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = toml.Unmarshal(content, &peers)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, peers)
}

func (a *UdpAgent) restartAgent(c *gin.Context) {
	err := a.RestartAgent()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"msg": "successfully restart agent"})
}

func (a *UdpAgent) getTeeStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"running":             a.IsRunning(),
		"attestationVerified": a.safeTee.Load(),
		"trustedByNHPServer":  a.trustedByNHPServer.Load(),
		"trustedByNHPDB":      a.trustedByNHPDB.Load(),
	})
}

func (a *UdpAgent) getTeeAttestation(c *gin.Context) {
	evidence, err := wasmEngine.GetEvidence()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, evidence)
}

func (a *UdpAgent) rotateAgentKey(c *gin.Context) {
	if err := a.RotateAgentKey(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := a.RestartAgent(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "successfully rotate agent key"})
}

func (a *UdpAgent) rotateTeeKey(c *gin.Context) {
	if err := a.RotateTeeKey(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := a.RestartAgent(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "successfully rotate TEE key"})
}
