import os
import shutil
import socket
import subprocess
import time
import unittest
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKE_TIMEOUT = 600
DOWN_TIMEOUT = 180
HTTP_WAIT_ATTEMPTS = 60
HTTP_WAIT_DELAY = 1
CADDY_CONTAINER = "ass-tut-caddy-1"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _make(target, env=None, timeout=MAKE_TIMEOUT):
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(
        ["make", target],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=full_env,
        timeout=timeout,
    )


def _http_status(url, timeout=5.0):
    try:
        with urlopen(url, timeout=timeout) as resp:
            return resp.status
    except (URLError, ConnectionResetError, socket.timeout, OSError):
        return None


def _wait_for_http_200(url, attempts=HTTP_WAIT_ATTEMPTS, delay=HTTP_WAIT_DELAY):
    for _ in range(attempts):
        if _http_status(url) == 200:
            return True
        time.sleep(delay)
    return False


def _container_running(name):
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0 and r.stdout.strip() == "true"


def _container_ports(name):
    r = subprocess.run(
        ["docker", "port", name],
        capture_output=True,
        text=True,
    )
    return r.stdout if r.returncode == 0 else ""


@unittest.skipUnless(_docker_available(), "docker not available on this host")
class ComposeModeSwitchTests(unittest.TestCase):
    def setUp(self):
        _make("down", timeout=DOWN_TIMEOUT)

    def tearDown(self):
        _make("down", timeout=DOWN_TIMEOUT)

    def test_make_http_serves_port_80(self):
        result = _make("http")
        self.assertEqual(result.returncode, 0, msg=f"make http failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")

        self.assertTrue(_wait_for_http_200("http://localhost/"), "frontend did not return 200 within timeout")
        self.assertTrue(_container_running(CADDY_CONTAINER))

        ports = _container_ports(CADDY_CONTAINER)
        self.assertIn("0.0.0.0:80", ports, f"caddy not bound to :80; ports={ports!r}")

    def test_switch_http_to_prod_does_not_collide_on_port_80(self):
        setup = _make("http")
        self.assertEqual(setup.returncode, 0, msg=f"http setup failed:\n{setup.stderr}")
        self.assertTrue(_wait_for_http_200("http://localhost/"))

        result = _make("prod", env={"DOMAIN": "localhost"})
        combined = (result.stdout + "\n" + result.stderr).lower()

        self.assertEqual(result.returncode, 0, msg=f"make prod after make http failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
        self.assertNotIn("port is already allocated", combined)
        self.assertNotIn("address already in use", combined)
        self.assertTrue(_container_running(CADDY_CONTAINER))

        ports = _container_ports(CADDY_CONTAINER)
        self.assertIn("80/tcp -> 0.0.0.0:80", ports, f"prod caddy missing :80 binding; ports={ports!r}")
        self.assertIn("443/tcp -> 0.0.0.0:443", ports, f"prod caddy missing :443 binding; ports={ports!r}")

    def test_switch_prod_to_http_unbinds_443(self):
        setup = _make("prod", env={"DOMAIN": "localhost"})
        self.assertEqual(setup.returncode, 0, msg=f"prod setup failed:\n{setup.stderr}")

        result = _make("http")
        combined = (result.stdout + "\n" + result.stderr).lower()

        self.assertEqual(result.returncode, 0, msg=f"make http after make prod failed:\n{result.stderr}")
        self.assertNotIn("port is already allocated", combined)
        self.assertNotIn("address already in use", combined)
        self.assertTrue(_wait_for_http_200("http://localhost/"))

        ports = _container_ports(CADDY_CONTAINER)
        self.assertIn("80/tcp -> 0.0.0.0:80", ports)
        self.assertNotIn("443/tcp -> 0.0.0.0:443", ports, f"http stack should not expose :443; ports={ports!r}")

    def test_make_down_releases_port_80(self):
        setup = _make("http")
        self.assertEqual(setup.returncode, 0)
        self.assertTrue(_wait_for_http_200("http://localhost/"))

        result = _make("down", timeout=DOWN_TIMEOUT)
        self.assertEqual(result.returncode, 0, msg=f"make down failed:\n{result.stderr}")
        self.assertFalse(_container_running(CADDY_CONTAINER))
        self.assertIsNone(_http_status("http://localhost/", timeout=2), "port 80 still serving after make down")


if __name__ == "__main__":
    unittest.main(verbosity=2)
