#!/usr/bin/python
import getopt
import logging
import os
import signal
import subprocess
import sys


def usage():
    print("""
usage: cni-plugin --role  [options]
common options:
  --server-bind-host                          ""
  --server-bind-port                          ""
  # --server-username                           ""
  # --server-password                           ""
  # --server-certfile                           ""
  # --server-keyfile                            ""
  # --server-cafile                             ""
  --etcd-servers                                ""
  --etcd-certfile                               ""
  --etcd-keyfile                                ""
  --etcd-cafile                                 ""
  --k8s-api-server                            "https://127.0.0.1:6443
  --k8s-ca                                    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
  --k8s-key                                   ""
  --k8s-cert                                  ""
  --k8s-token                                 ""
  --log-dir                                  "/var/log/sdnc-net-plugin/"
  --log-level                                "1"
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
    server_bind_host = ""
    server_bind_port = "9443"
    etcd_servers = ""
    etcd_certfile = ""
    etcd_keyfile = ""
    etcd_cafile = ""
    # server_username = ""
    # server_password = ""
    # server_protocol = ""
    # server_certfile = ""
    # server_keyfile = ""
    # server_cafile = ""
    k8s_api_server = "https://2.2.0.15:6443"
    k8s_ca = "/etc/cni-plugin/ca.crt"
    k8s_key = "/etc/cni-plugin/apiserver-kubelet-client.key"
    k8s_cert = "/etc/cni-plugin/apiserver-kubelet-client.crt"
    k8s_token = ""
    log_dir = "/var/log/cni-plugin/"
    log_level = "1"

    longopts = [
        "server-bind-host=",
        "server-bind-port=",
        # "server-username=",
        # "server-password=",
        # "server-protocol=",
        # "server-certfile=",
        # "server-keyfile=",
        # "server-cafile=",
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
        LOG.error("failed to parse command sdnc-net-server, exception is %s", e)
        return

    for name, value in opts:
        if name == "--server-bind-host":
            server_bind_host = value
        if name == "--server-bind-port":
            server_bind_port = value
        # if name == "--server-username":
        #     server_username = value
        # if name == "--server-password":
        #     server_password = value
        # if name == "--server-protocol":
        #     server_protocol = value
        # if name == "--server-certfile":
        #     server_certfile = value
        # if name == "--server-keyfile":
        #     server_keyfile = value
        # if name == "--server-cafile":
        #     server_cafile = value
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
    os.system('/usr/bin/cp /cni-plugin/01-demo-cni.conf /etc/cni/net.d/ -f')
    os.system('/usr/bin/cp /cni-plugin/bin/cni-plugin /opt/cni/bin -f')

    command = ['/sdnc-net-server/bin/server',
               '--server-bind-host', server_bind_host,
               '--server-bind-port', server_bind_port,
               # '--server-username', server_username,
               # '--server-password', server_password,
               # '--server-protocol', server_protocol,
               # '--server-certfile', server_certfile,
               # '--server-keyfile', server_keyfile,
               # '--server-cafile', server_cafile,
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

    try:
        ret = subprocess.check_output(command, universal_newlines=True)
        LOG.debug("command %s, return value is %s", command, ret)
    except Exception as e:
        LOG.error("failed to execute command %s, exception is %s", command, e)


if __name__ == "__main__":
    sys.exit(main())
