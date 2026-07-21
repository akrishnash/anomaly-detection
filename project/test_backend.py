import os
import sys
import unittest
import pandas as pd
import numpy as np

# Ensure backend folder is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "backend")))

import database
import preprocessing
import isolation_forest
import anomaly_detector
import ddos_classifier
import shap_explainer

class TestIDSBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize database
        database.init_db()

    def test_database_settings(self):
        # Verify default settings are present
        settings = database.get_settings()
        self.assertIn("context_window", settings)
        self.assertIn("model_selection", settings)
        
        # Test updating settings
        database.save_setting("test_key", "test_val")
        self.assertEqual(database.get_setting("test_key"), "test_val")

    def test_model_loading(self):
        # Verify model files exist and load successfully
        try:
            scaler, meta, autoencoder = preprocessing.load_preprocessor_assets()
            self.assertIsNotNone(scaler)
            self.assertIsNotNone(meta)
            self.assertIsNotNone(autoencoder)
            
            if_model = isolation_forest.load_isolation_forest()
            self.assertIsNotNone(if_model)

            # Ensemble calibration anchors must be present for unsupervised scoring
            self.assertIn("calibration", meta)
            self.assertIn("if", meta["calibration"])
            self.assertIn("ae", meta["calibration"])
        except FileNotFoundError:
            self.fail("Trained model files are missing from project/models/")

    def test_pipeline_inference(self):
        # Test running a mock data slice through the preprocessor and models
        mock_flow = pd.DataFrame([{
            "flow_byts_s": 50000.0,
            "flow_pkts_s": 100.0,
            "fwd_bytes": 1000.0,
            "bwd_bytes": 2000.0,
            "total_pkts": 15,
            "syn_flag": 1,
            "rst_flag": 0,
            "fin_flag": 0,
            "flow_duration_s": 0.15,
            "pkt_len_mean": 200.0
        }])
        
        # 1. Preprocessing
        X_scaled, feature_names = preprocessing.preprocess_features(mock_flow)
        self.assertEqual(X_scaled.shape, (1, 10))
        
        # 2. Isolation Forest
        if_scores = isolation_forest.compute_anomaly_scores(X_scaled)
        self.assertEqual(len(if_scores), 1)

        # 3. Unsupervised ensemble scoring (IF + Autoencoder, calibrated to [0, 1])
        probs, if_scores2, ae_scores = anomaly_detector.score_flows(X_scaled)
        self.assertEqual(len(probs), 1)
        self.assertTrue(0.0 <= probs[0] <= 1.0)
        self.assertEqual(len(ae_scores), 1)

        # 4. SHAP explainability (explains the Isolation Forest on the 10 base features)
        contributions, text_explanation = shap_explainer.explain_prediction(X_scaled[0])
        self.assertEqual(len(contributions), 10)
        self.assertTrue(isinstance(text_explanation, str))

    def test_ddos_rule_engine(self):
        # SYN flood: SYN-dominant, half-open, no response traffic
        syn_flood = {
            "protocol": "TCP", "src_port": 44231, "dst_port": 80,
            "total_pkts": 200, "flow_pkts_s": 400.0, "flow_byts_s": 24000.0,
            "pkt_len_mean": 60.0, "flow_duration_s": 0.5,
            "fwd_bytes": 12000.0, "bwd_bytes": 0.0,
            "syn_flag": 200, "rst_flag": 0, "fin_flag": 0, "ack_flag": 0
        }
        v = ddos_classifier.classify_flow(syn_flood)
        self.assertEqual(v["attack_type"], "SYN Flood")
        self.assertIn(v["severity"], ["High", "Critical"])

        # UDP flood: high-rate one-directional UDP
        udp_flood = {
            "protocol": "UDP", "src_port": 55000, "dst_port": 5060,
            "total_pkts": 5000, "flow_pkts_s": 900.0, "flow_byts_s": 500000.0,
            "pkt_len_mean": 512.0, "flow_duration_s": 5.5,
            "fwd_bytes": 2500000.0, "bwd_bytes": 0.0,
            "syn_flag": 0, "rst_flag": 0, "fin_flag": 0, "ack_flag": 0
        }
        v = ddos_classifier.classify_flow(udp_flood)
        self.assertEqual(v["attack_type"], "UDP Flood")

        # DNS amplification: reflected oversized responses from port 53
        dns_amp = {
            "protocol": "UDP", "src_port": 53, "dst_port": 33812,
            "total_pkts": 800, "flow_pkts_s": 160.0, "flow_byts_s": 2400000.0,
            "pkt_len_mean": 3000.0, "flow_duration_s": 5.0,
            "fwd_bytes": 12000000.0, "bwd_bytes": 10000.0,
            "syn_flag": 0, "rst_flag": 0, "fin_flag": 0, "ack_flag": 0
        }
        v = ddos_classifier.classify_flow(dns_amp)
        self.assertIn("Amplification", v["attack_type"])
        self.assertIn("DNS", v["attack_type"])

        # ICMP flood
        icmp_flood = {
            "protocol": "ICMP", "src_port": 0, "dst_port": 0,
            "total_pkts": 1000, "flow_pkts_s": 300.0, "flow_byts_s": 84000.0,
            "pkt_len_mean": 84.0, "flow_duration_s": 3.3,
            "fwd_bytes": 84000.0, "bwd_bytes": 0.0,
            "syn_flag": 0, "rst_flag": 0, "fin_flag": 0, "ack_flag": 0
        }
        v = ddos_classifier.classify_flow(icmp_flood)
        self.assertEqual(v["attack_type"], "ICMP Flood")

        # Benign-shaped anomaly should NOT be forced into a DDoS label
        odd_but_calm = {
            "protocol": "TCP", "src_port": 51000, "dst_port": 8443,
            "total_pkts": 6, "flow_pkts_s": 1.2, "flow_byts_s": 800.0,
            "pkt_len_mean": 640.0, "flow_duration_s": 5.0,
            "fwd_bytes": 2400.0, "bwd_bytes": 1600.0,
            "syn_flag": 1, "rst_flag": 0, "fin_flag": 1, "ack_flag": 5
        }
        v = ddos_classifier.classify_flow(odd_but_calm)
        self.assertEqual(v["attack_type"], "Unknown Anomaly")

    def test_campaign_aggregation(self):
        # 40 spoofed sources SYN-flooding one target -> distributed campaign
        flows = []
        for k in range(40):
            flows.append({
                "id": k, "src_ip": f"203.0.113.{k + 1}", "dst_ip": "10.0.0.5",
                "dst_port": 80, "attack_type": "SYN Flood", "severity": "High",
                "total_pkts": 3
            })
        campaigns, refinements = ddos_classifier.aggregate_campaigns(flows)

        self.assertEqual(len(campaigns), 1)
        c = campaigns[0]
        self.assertTrue(c["distributed"])
        self.assertEqual(c["target"], "10.0.0.5")
        self.assertEqual(c["num_sources"], 40)
        self.assertEqual(c["severity"], "Critical")
        self.assertIn("DDoS", c["label"])
        self.assertIn("SYN Flood", c["label"])
        # All flows of the dominant type get upgraded to a DDoS verdict,
        # with a traceable reason attached
        self.assertEqual(refinements[0][:2], ("DDoS: SYN Flood", "Critical"))
        self.assertIn("10.0.0.5", refinements[0][2])
        self.assertIn("40 unique sources", refinements[0][2])

        # One source probing many ports -> port scan, not a DDoS
        scan_flows = []
        for k in range(25):
            scan_flows.append({
                "id": k, "src_ip": "198.51.100.7", "dst_ip": "10.0.0.9",
                "dst_port": k + 1, "attack_type": "SYN Flood", "severity": "High",
                "total_pkts": 1
            })
        campaigns, refinements = ddos_classifier.aggregate_campaigns(scan_flows)
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0]["attack_type"], "Port Scan / Recon")
        self.assertEqual(refinements[0][:2], ("Port Scan / Recon", "High"))
        self.assertIn("198.51.100.7", refinements[0][2])

    def test_api_endpoints(self):
        # Use TestClient to run endpoints
        try:
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            
            # Status check
            res = client.get("/api/online/status")
            self.assertEqual(res.status_code, 200)
            self.assertFalse(res.json()["is_running"])
            
            # Settings check
            res = client.get("/api/settings")
            self.assertEqual(res.status_code, 200)
            self.assertIn("model_selection", res.json())
            
            # Health check
            res = client.get("/api/metrics")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["status"], "Green")
        except ImportError:
            # TestClient requires httpx, skip if not installed
            pass

    def test_canonical_preprocessing(self):
        # 1. Test alias resolution and normalization
        raw_df = pd.DataFrame([{
            "Source IP": "192.168.2.1",
            "ip.dst": "10.0.2.15",
            "sport": 443,
            "Destination Port": 50123,
            "protocol": "TCP",
            "Flow Duration": 2500000.0,
            "packets": 100,
            "bytes": 50000,
            "syn_flag_cnt": 3
        }], index=[42]) # custom index
        
        # Preprocessing should resolve aliases and construct canonical schema
        X_scaled, feature_names, df_canonical = preprocessing.preprocess_dataset(raw_df)
        
        # Verify custom index is preserved
        self.assertEqual(list(df_canonical.index), [42])
        self.assertEqual(list(X_scaled.shape), [1, 10])
        
        # Verify resolved aliases
        self.assertEqual(df_canonical.loc[42, "src_ip"], "192.168.2.1")
        self.assertEqual(df_canonical.loc[42, "dst_ip"], "10.0.2.15")
        self.assertEqual(df_canonical.loc[42, "src_port"], 443)
        self.assertEqual(df_canonical.loc[42, "dst_port"], 50123)
        self.assertEqual(df_canonical.loc[42, "duration"], 2.5)
        self.assertEqual(df_canonical.loc[42, "packets"], 100)
        self.assertEqual(df_canonical.loc[42, "bytes"], 50000)
        self.assertEqual(df_canonical.loc[42, "syn_count"], 3)
        
        # Verify missing feature fallback
        self.assertEqual(df_canonical.loc[42, "ack_count"], 0)
        self.assertEqual(df_canonical.loc[42, "flow_id"], "")
        
        # 2. Test validation error when ALL required features are missing
        invalid_df = pd.DataFrame([{
            "Source IP": "192.168.2.1",
            "ip.dst": "10.0.2.15"
        }])
        
        with self.assertRaises(ValueError) as context:
            preprocessing.preprocess_dataset(invalid_df)
        self.assertIn("Unable to construct canonical schema. Missing required features", str(context.exception))
        
        # 3. Test custom web sessions schema (should process successfully with fallback for missing packets)
        web_df = pd.DataFrame([{
            "session_id": "SID_00001",
            "network_packet_size": 599,
            "protocol_type": "TCP",
            "session_duration": 492.98
        }])
        
        X_scaled_web, _, df_canonical_web = preprocessing.preprocess_dataset(web_df)
        self.assertEqual(df_canonical_web.loc[0, "flow_id"], "SID_00001")
        self.assertEqual(df_canonical_web.loc[0, "bytes"], 599)
        self.assertEqual(df_canonical_web.loc[0, "protocol"], "TCP")
        self.assertEqual(df_canonical_web.loc[0, "duration"], 492.98)
        self.assertEqual(df_canonical_web.loc[0, "packets"], 0) # fallback default
        self.assertEqual(X_scaled_web.shape, (1, 10))

    def test_history_stats_and_exports(self):
        # Test get_history_stats
        stats = database.get_history_stats()
        self.assertIn("total_records", stats)
        self.assertIn("first_captured", stats)
        self.assertIn("latest_captured", stats)
        self.assertIn("interval_seconds", stats)
        self.assertIn("formatted_duration", stats)
        self.assertIn("anomaly_count", stats)
        self.assertIn("benign_count", stats)

        # Test FastAPI export endpoints via TestClient
        from api import router
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        
        # Test GET /api/history/stats
        r1 = client.get("/api/history/stats")
        self.assertEqual(r1.status_code, 200)
        self.assertIn("formatted_duration", r1.json())

        # Test GET /api/export-json
        r2 = client.get("/api/export-json")
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.headers.get("content-type", "").startswith("application/json"))

        # Test GET /api/export-csv
        r3 = client.get("/api/export-csv")
        self.assertEqual(r3.status_code, 200)
        self.assertTrue(r3.headers.get("content-type", "").startswith("text/csv"))

        # Test GET /api/download-pdf
        r4 = client.get("/api/download-pdf")
        self.assertEqual(r4.status_code, 200)
        self.assertTrue(r4.headers.get("content-type", "").startswith("application/pdf"))

if __name__ == "__main__":
    unittest.main()

