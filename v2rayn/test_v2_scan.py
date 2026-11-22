import unittest
from unittest.mock import patch, Mock
import v2_scan

RANGES = """173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
"""

class ScannerTests(unittest.TestCase):
    def test_candidate_count_and_rotation(self):
        a=v2_scan.get_candidates(limit=200,rotation=42,ranges_text=RANGES)
        b=v2_scan.get_candidates(limit=200,rotation=42,ranges_text=RANGES)
        c=v2_scan.get_candidates(limit=200,rotation=43,ranges_text=RANGES)
        self.assertEqual(len(a),200)
        self.assertEqual(a,b)
        self.assertNotEqual(a,c)
        self.assertEqual(len(set(a)),200)
        self.assertIn("104.17.99.242",a)

    def test_vless_template_and_xray_config(self):
        uri="vless://11111111-1111-4111-8111-111111111111@edge.example:443?security=tls&type=ws&sni=origin.example&host=ws.example&path=%2Fsecret%3Fed%3D2048&fp=chrome"
        t=v2_scan.parse_template(uri)
        config=v2_scan.make_xray_config(t,"104.17.99.242",12345)
        stream=config["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["tlsSettings"]["serverName"],"origin.example")
        self.assertEqual(stream["wsSettings"]["headers"]["Host"],"ws.example")
        self.assertEqual(stream["wsSettings"]["path"],"/secret?ed=2048")
        self.assertEqual(config["outbounds"][0]["settings"]["vnext"][0]["address"],"104.17.99.242")
        self.assertEqual(config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"],t["id"])

    def test_missing_template_rejected(self):
        with self.assertRaises(ValueError):
            v2_scan.parse_template("")
        with self.assertRaises(ValueError):
            v2_scan.parse_template("vless://bad@edge.example:443?security=tls&type=ws&sni=example.org")

    @patch("v2_scan.subprocess.run")
    def test_tls_failure_does_not_count_as_real_vless(self, run):
        run.return_value = Mock(stdout="200 0.120")
        result=v2_scan.tls_check("104.17.99.242","origin.example",5)
        self.assertEqual(result["https_ms"],120)
        self.assertNotIn("vless_verified",result)
        self.assertIn("--resolve",run.call_args.args[0])

    @patch("v2_scan.subprocess.run")
    def test_http_403_is_accepted_as_tls_reachability(self,run):
        run.return_value = Mock(stdout="403 0.120")
        result=v2_scan.tls_check("104.17.99.242","origin.example",5)
        self.assertIsNotNone(result)
        self.assertNotIn("-f",run.call_args.args[0])


    @patch("v2_scan.time.sleep")
    @patch("v2_scan.subprocess.Popen")
    @patch("v2_scan.subprocess.run")
    def test_real_vless_result_requires_successful_proxied_http(self, run, popen, sleep):
        proc=Mock()
        proc.poll.return_value=None
        popen.return_value=proc
        c={"ip":"104.17.99.242","https_ms":100,"https_status":200}
        template=v2_scan.parse_template(
            "vless://11111111-1111-4111-8111-111111111111@edge.example:443?security=tls&type=ws&sni=origin.example&host=ws.example&path=%2F")
        run.return_value=Mock(returncode=28,stdout="000 0.000")
        self.assertIsNone(v2_scan.probe_vless(c,template))
        run.return_value=Mock(returncode=0,stdout="200 0.425")
        r=v2_scan.probe_vless(c,template)
        self.assertTrue(r["vless_verified"])
        self.assertEqual(r["latency_ms"],425)
        cmd=run.call_args.args[0]
        self.assertIn("--proxy",cmd)
        self.assertIn("socks5h://", " ".join(cmd))

if __name__=="__main__": unittest.main()
