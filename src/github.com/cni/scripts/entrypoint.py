#!/usr/bin/python
import getopt
import logging
import os
import signal
import subprocess
import sys


def usage():
    print("""
usage: cni-plugin --role {master | node} [options]
common options:
  --etcd-servers                                ""
  --etcd-certfile                               ""
  --etcd-keyfile                                ""
  --etcd-cafile                                 ""
  --k8s-api-server                            "https://127.0.0.1:6443
  --k8s-ca                                    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
  --k8s-key                                   ""
  --k8s-cert                                  ""
  --k8s-token                                 ""
  --log-dir                                  "/var/log/cni-plugin/"
  --log-level                                "1"
master options:
  --bind-host                                   ""
  --bind-port                                   ""
  --webhook-bind-port                           ""
  --tlsCertPath                                 ""
  --tlsKeyPath                                  ""
node options:
  --agent-host                                  ""
  --agent-port                                  ""
    """)


def main():
    def signal_handle(signum, frame):
        LOG.debug("destroy cni-agent container,signum is %s", signum)

    signal.signal(signal.SIGINT, signal_handle)
    signal.signal(signal.SIGTERM, signal_handle)
    stdout_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s")
    stdout_handler.setFormatter(formatter)
    LOG = logging.getLogger()
    LOG.setLevel(logging.DEBUG)
    LOG.addHandler(stdout_handler)
    role = ""
    etcd_servers = ""
    etcd_certfile = ""
    etcd_keyfile = ""
    etcd_cafile = ""
    k8s_api_server = "https://2.2.0.15:6443"
    k8s_ca = "/etc/cni-plugin/ca.crt"
    k8s_key = "/etc/cni-plugin/apiserver-kubelet-client.key"
    k8s_cert = "/etc/cni-plugin/apiserver-kubelet-client.crt"
    k8s_token = ""
    log_dir = "/var/log/cni-plugin/"
    log_level = "1"

    # master options

    bind_host = ""
    bind_port = "9100"
    webhook_bind_port = "9101"
    tlsCertPath = ""
    tlsKeyPath = ""

    # node options

    agent_host = ""
    agent_port = ""

    longopts = [
        "role=",
        "bind-host=",
        "bind-port=",
        "webhook-bind-port=",
        "tlsCertPath=",
        "tlsKeyPath=",
        "agent-host=",
        "agent-port=",
        "etcd-servers=",
        "etcd-certfile=",
        "etcd-keyfile=",
        "etcd-cafile=",
        "k8s-api-server=",
        "k8s-ca=",
        "k8s-key=",
        "k8s-cert=",
        "k8s-token=",
        "log-dir=",
        "log-level=",
    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:], "", longopts)
    except Exception as e:
        LOG.error("failed to parse command cni-plugin, exception is %s", e)
        return

    for name, value in opts:
        if name == "--role":
            role = value

        if name == "--etcd-servers":
            etcd_servers = value
        if name == "--etcd-certfile":
            etcd_certfile = value
        if name == "--etcd-keyfile":
            etcd_keyfile = value
        if name == "--etcd-cafile":
            etcd_cafile = value
        if name == "--k8s-api-server":
            k8s_api_server = value
        if name == "--k8s-ca":
            k8s_ca = value
        if name == "--k8s-key":
            k8s_key = value
        if name == "--k8s-cert":
            k8s_cert = value
        if name == "--k8s-token":
            k8s_token = value
        if name == "--log-dir":
            log_dir = value
        if name == "--log-level":
            log_level = value
        # master options
        if name == "--bind-host":
            bind_host = value
        if name == "--bind-port":
            bind_port = value
        if name == "--webhook-bind-port":
            webhook_bind_port = value
        if name == "--tlsCertPath":
            tlsCertPath = value
        if name == "--tlsKeyPath":
            tlsKeyPath = value

        # node options
        if name == "--agent-host":
            agent_host = value
        if name == "--agent-port":
            agent_port = value
    if role == "master":
        command = ['/cni-plugin/bin/master-agent',
                   '--bind-host', bind_host,
                   '--bind-port', bind_port,
                   '--etcd-servers', etcd_servers,
                   '--etcd-certfile', etcd_certfile,
                   '--etcd-keyfile', etcd_keyfile,
                   '--etcd-cafile', etcd_cafile,
                   '--k8s-api-server', k8s_api_server,
                   '--k8s-ca', k8s_ca,
                   '--k8s-key', k8s_key,
                   '--k8s-cert', k8s_cert,
                   '--k8s-token', k8s_token,
                   '--webhook-bind-port', webhook_bind_port,
                   '--tlsCertPath', tlsCertPath,
                   '--tlsKeyPath', tlsKeyPath,
                   '--log-dir', log_dir,
                   '--v', log_level,
                   ]
    elif role == "node":
        os.system('/usr/bin/cp /cni-plugin/01-demo-cni.conf /etc/cni/net.d/ -f')
        os.system('/usr/bin/cp /cni-plugin/bin/cni-plugin /opt/cni/bin -f')

        command = ['/cni-plugin/bin/node-agent',
                   '--agent-host', agent_host,
                   '--agent-port', agent_port,
                   '--etcd-servers', etcd_servers,
                   '--etcd-certfile', etcd_certfile,
                   '--etcd-keyfile', etcd_keyfile,
                   '--etcd-cafile', etcd_cafile,
                   '--k8s-api-server', k8s_api_server,
                   '--k8s-ca', k8s_ca,
                   '--k8s-key', k8s_key,
                   '--k8s-cert', k8s_cert,
                   '--k8s-token', k8s_token,
                   '--log-dir', log_dir,
                   '--v', log_level,
                   ]
    else:
        LOG.error("cni-plugin requires '--role {master | node}'.")
        usage()
        return

    try:
        ret = subprocess.check_output(command, universal_newlines=True)
        LOG.debug("command %s, return value is %s", command, ret)
    except Exception as e:
        LOG.error("failed to execute command %s, exception is %s", command, e)


if __name__ == "__main__":
    sys.exit(main())
