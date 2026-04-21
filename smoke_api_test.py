import importlib
import os
import tempfile
import unittest
from pathlib import Path


class AutoShieldAPISmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        os.environ["AUTOSHIELD_DB"] = str(Path(cls._tmp.name) / "smoke_autoshield.db")

        import db
        import auth
        import api_layer

        importlib.reload(db)
        importlib.reload(auth)
        importlib.reload(api_layer)

        from fastapi.testclient import TestClient

        cls.api = api_layer
        cls.client = TestClient(api_layer.create_app())

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_auth_context_contains_tier_and_site(self):
        res = self.client.post(
            "/auth/login", json={"username": "admin", "password": "admin123"}
        )
        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertIn("token", payload)
        self.assertIn("context", payload)
        self.assertEqual(payload["context"]["tier"], "premium")
        self.assertIn("primary_site", payload["context"])
        self.assertIn("sites", payload["context"])

    def test_demo_free_and_premium_credentials_work(self):
        premium = self.client.post(
            "/auth/login", json={"username": "premium.demo", "password": "premium123"}
        )
        self.assertEqual(premium.status_code, 200)
        self.assertEqual(premium.json()["context"]["tier"], "premium")

        free = self.client.post(
            "/auth/login", json={"username": "free.demo", "password": "free123"}
        )
        self.assertEqual(free.status_code, 200)
        self.assertEqual(free.json()["context"]["tier"], "free")

    def test_events_stats_and_health_endpoints(self):
        login = self.client.post(
            "/auth/login", json={"username": "admin", "password": "admin123"}
        )
        self.assertEqual(login.status_code, 200)
        body = login.json()
        token = body["token"]
        site_id = body["context"]["primary_site"]["id"]
        headers = {"X-AutoShield-Key": token}

        ingest = self.client.post(
            "/events",
            headers=headers,
            json={
                "src_ip": "203.0.113.10",
                "payload": "GET /?q=' OR 1=1 -- HTTP/1.1",
                "ingestion_source": "smoke_test",
            },
        )
        self.assertEqual(ingest.status_code, 201)

        events = self.client.get("/events?limit=5", headers=headers)
        self.assertEqual(events.status_code, 200)
        events_body = events.json()
        self.assertGreaterEqual(events_body["count"], 1)

        stats = self.client.get("/stats", headers=headers)
        self.assertEqual(stats.status_code, 200)
        stats_body = stats.json()
        self.assertIn("total", stats_body)
        self.assertIn("blocked", stats_body)

        health = self.client.get(f"/sites/health?site_id={site_id}", headers=headers)
        self.assertEqual(health.status_code, 200)
        health_body = health.json()
        self.assertEqual(health_body["site_id"], site_id)
        self.assertIn("latency_ms", health_body)
        self.assertIn("reachable", health_body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
