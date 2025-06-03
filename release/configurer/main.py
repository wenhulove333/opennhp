import argparse
import platform
import re
import subprocess
import tomlkit

curve = "sm2" # sm2 or 25519
keygen_exec = ""
server_ip = ""

class ECCKeyGen():
    def __init__(self):
        self._generate()

    def _extract_keys_from_output(self, output):
        private_key_pattern = r'Private key:\s*([A-Za-z0-9+/=]+)'
        public_key_pattern = r'Public key:\s*([A-Za-z0-9+/=]+)'

        private_match = re.search(private_key_pattern, output)
        private_key = private_match.group(1) if private_match else None

        public_match = re.search(public_key_pattern, output)
        public_key = public_match.group(1) if public_match else None

        return private_key, public_key

    def _generate(self):
        options = "--curve"
        if curve == "sm2":
            options = "--sm2"
        try:
            result = subprocess.run(
                [keygen_exec, "keygen", options],
                check=True,
                capture_output=True,
                text=True
            )

            self._private_key, self._public_key = self._extract_keys_from_output(result.stdout)
        except subprocess.CalledProcessError as e:
            raise Exception("fail to execute command, and error info: " + e.stderr)

    @property
    def PrivateKeyBase64(self):
        return self._private_key

    @property
    def PublicKeyBase64(self):
        return self._public_key


class Base():
    def __init__(self, path):
        self._path = path
        with open(path, mode="rt", encoding="utf-8") as fp:
            self._config = tomlkit.load(fp)

    def ExtraConfig(self, key, value):
        self._config[key] = value
        with open(self._path, mode="wt", encoding="utf-8") as fp:
            tomlkit.dump(self._config, fp)

class Config(Base):
    def __init__(self, path):
        super().__init__(path)
        self._keygen = ECCKeyGen()
        self._config["PrivateKeyBase64"] = self._keygen.PrivateKeyBase64
        # save back to file
        with open(path, mode="wt", encoding="utf-8") as fp:
            tomlkit.dump(self._config, fp)

    @property
    def PrivateKeyBase64(self):
        return self._keygen.PrivateKeyBase64

    @property
    def PublicKeyBase64(self):
        return self._keygen.PublicKeyBase64

class Server(Base):
    def __init__(self, path, server):
        super().__init__(path)
        self._server = server
        self._config["Servers"][0]["PubKeyBase64"] = self._server.PublicKeyBase64
        global server_ip
        if server_ip != "":
            self._config["Servers"][0]["Ip"] = server_ip
        with open(path, mode="wt", encoding="utf-8") as fp:
            tomlkit.dump(self._config, fp)

class Client(Base):
    def __init__(self, path, client, type): # type: ACs, Agents, DEs
        super().__init__(path)
        self._client = client
        self._config[type][0]["PubKeyBase64"] = self._client.PublicKeyBase64
        with open(path, mode="wt", encoding="utf-8") as fp:
            tomlkit.dump(self._config, fp)

class Consumer(Base):
    def __init__(self, path, agent):
        super().__init__(path)
        self._agent = agent
        self._config["Consumers"][0]["ConsumerPublicKeyBase64"] = self._agent.PublicKeyBase64
        with open(path, mode="wt", encoding="utf-8") as fp:
            tomlkit.dump(self._config, fp)
    def ExtraConfig(self, key, value):
        self._config["Consumers"][0][key] = value
        with open(self._path, mode="wt", encoding="utf-8") as fp:
            tomlkit.dump(self._config, fp)

class Configurer():
    def __init__(self, release_path):
        self._release_path = release_path
        self._server = Config(self._release_path + "/nhp-server/etc/config.toml")
        self._agent = Config(self._release_path + "/nhp-agent/etc/config.toml")
        teeKeyGen = ECCKeyGen()
        self._agent.ExtraConfig("TEEPrivateKeyBase64", teeKeyGen.PrivateKeyBase64)
        self._de = Config(self._release_path + "/nhp-de/etc/config.toml")
        self._ac = Config(self._release_path + "/nhp-ac/etc/config.toml")
        if platform.system() != "Windows":
            self._agent.ExtraConfig("DHPExeCMD", "../nhp-de/nhp-de")

        self._agent_server = Server(self._release_path + "/nhp-agent/etc/server.toml", self._server)
        self._de_server = Server(self._release_path + "/nhp-de/etc/server.toml", self._server)
        self._ac_server = Server(self._release_path + "/nhp-ac/etc/server.toml", self._server)

        self._server_agent = Client(self._release_path + "/nhp-server/etc/agent.toml", self._agent, "Agents")
        self._server_de = Client(self._release_path + "/nhp-server/etc/de.toml", self._de, "DEs")
        self._server_ac = Client(self._release_path + "/nhp-server/etc/ac.toml", self._ac, "ACs")

        self._consumer = Consumer(self._release_path + "/nhp-de/etc/consumer.toml", self._agent)
        self._consumer.ExtraConfig("TEEPublicKeyBase64", teeKeyGen.PublicKeyBase64)


def main():
    parser = argparse.ArgumentParser(description='Configure the OpenNHP, mainly for related keys')
    parser.add_argument('--release-path', help='the path of the release folder', required=True)
    parser.add_argument('--curve', help='the curve type, default is sm2', choices=['sm2', '25519'], default="sm2")
    parser.add_argument('--server-ip', help='the ip of the server', default="")

    args = parser.parse_args()

    global curve, keygen_exec, server_ip
    curve = args.curve
    server_ip = args.server_ip
    keygen_exec = args.release_path + "/nhp-agent/nhp-agentd"

    Configurer(args.release_path)

if __name__ == "__main__":
    main()
