package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/OpenNHP/opennhp/nhp/log"
)

var (
	taApiPrefix = fmt.Sprintf("%s/ta", serviceApiPrefix)
)

type TAFunctionParam struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type    string       `json:"type"`
}

type TAFunction struct {
	Method      string                    `json:"method"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Params      []TAFunctionParam         `json:"params"`
}

type TrustedApplication struct {
	Path          string                  `json:"path"`
	Functions     []TAFunction            `json:"functions"`
}
func NewTrustApplication(trustedApp string) (*TrustedApplication, error) {
	ta := &TrustedApplication{
		Path: filepath.Base(trustedApp),
		Functions: []TAFunction{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var c *client.Client
	var err error

	stdioTransport := transport.NewStdio(trustedApp, nil)
	c = client.NewClient(stdioTransport)

	if err := c.Start(ctx); err != nil {
		log.Error("Failed to start trusted application: %v", err)
		return nil, err
	}


	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{
		Name:    "Trusted Application Executor",
		Version: "1.0.0",
	}
	initRequest.Params.Capabilities = mcp.ClientCapabilities{}

	_, err = c.Initialize(ctx, initRequest)
	if err != nil {
		log.Error("Failed to initialize: %v", err)
		return nil, err
	}

	toolsRequest := mcp.ListToolsRequest{}
	toolsResult, err := c.ListTools(ctx, toolsRequest)
	if err != nil {
		log.Error("Failed to list functions which are supported in trusted application: %v", err)
		return nil, err
	} else {
		for _, tool := range toolsResult.Tools {
			taFunc := TAFunction{
				Method:      "POST",
				Name:        fmt.Sprintf("%s/%s/%s", taApiPrefix, ta.Path, tool.Name),
				Description: tool.Description,
				Params: []TAFunctionParam{
					{
						Name:        "doId",
						Description: "identifier of the data object",
						Type:    "string",
					},
				},
			}

			schema := tool.InputSchema
			for name, propSchema := range schema.Properties {
				if name == "path" { // path is injected by nhp agent
					continue
				}
				prop, _ := propSchema.(map[string]any)
				taFuncParam := TAFunctionParam{
					Name:        name,
					Description: prop["description"].(string),
					Type:    prop["type"].(string),
				}
				taFunc.Params = append(taFunc.Params, taFuncParam)
			}
			ta.Functions = append(ta.Functions, taFunc)
		}
	}

	return ta, nil
}

func (ta *TrustedApplication) GetSupportedFunctions() []TAFunction {
    return ta.Functions
}

func (ta *TrustedApplication) CallFunction(trustedApp string, function string, params map[string]any) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var c *client.Client
	var err error

	stdioTransport := transport.NewStdio(trustedApp, nil)
	c = client.NewClient(stdioTransport)

	if err := c.Start(ctx); err != nil {
		log.Error("Failed to start trusted application: %v", err)
		return "", err
	}


	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{
		Name:    "Trusted Application Executor",
		Version: "1.0.0",
	}
	initRequest.Params.Capabilities = mcp.ClientCapabilities{}

	_, err = c.Initialize(ctx, initRequest)
	if err != nil {
		log.Error("Failed to initialize: %v", err)
		return "", err
	}

	callRequest := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: function,
			Arguments: params,
		},
	}

	callResponse, err := c.CallTool(ctx, callRequest)
	if err != nil {
		return "", err
	}

	// check the type of content
	switch firstContent := callResponse.Content[0].(type) {
		case mcp.TextContent:
			return firstContent.Text, nil
		default:
			return "", fmt.Errorf("unexpected content type: %T", callResponse.Content[0])
	}
}