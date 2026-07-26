import string
from elasticsearch import Elasticsearch, helpers
import pandas as pd
from sklearn.ensemble import IsolationForest

es = Elasticsearch(["http://localhost:9200"])

def extract_features(raw_text, status_code, method, tags):
    text_str = str(raw_text)

    uri_length = len(text_str)
    special_chars = set(string.punctuation)
    special_char_count = sum(1 for char in text_str if char in special_chars)
    special_char_ratio = (special_char_count / uri_length) if uri_length > 0 else 0.0
    digit_count = sum(1 for char in text_str if char.isdigit())

    try:
        status = int(status_code)
    except (ValueError, TypeError):
        status = 200

    is_post = 1 if str(method).upper() == "POST" else 0

    has_xss_tag = 1 if 'xss_attempt' in tags else 0
    has_sqli_tag = 1 if 'sqli_attempt' in tags else 0
    has_brute_tag = 1 if 'brute_force_attempt' in tags else 0
    has_csrf_tag = 1 if 'csrf_attempt' in tags else 0

    return [
        uri_length,
        special_char_count,
        special_char_ratio,
        digit_count,
        status,
        is_post,
        has_xss_tag,
        has_sqli_tag,
        has_brute_tag,
        has_csrf_tag
    ]

def run_ai_detection():
    # Only pull logs from the last 24 hours — keeps old, pre-fix / stale
    # untagged logs out of the "clean" training baseline
    all_query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "request_path"}}
                ],
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-1d"}}}
                ]
            }
        },
        "size": 1000,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    try:
        response = es.search(index="logstash-*", body=all_query)
        hits = response['hits']['hits']

        if not hits:
            print("[-] No clean HTTP web access logs found in Elasticsearch.")
            return

        print(f"[+] Processing {len(hits)} total HTTP web logs...")

        all_docs = []
        clean_docs = []
        attack_tags = {'xss_attempt', 'sqli_attempt', 'brute_force_attempt', 'csrf_attempt'}

        for hit in hits:
            source = hit['_source']
            doc_id = hit['_id']
            index_name = hit['_index']

            raw_msg = source.get('request_path') or source.get('message') or source.get('event', {}).get('original', '')
            status_code = source.get('response', source.get('http_status', 200))
            http_method = source.get('verb', source.get('http_method', 'GET'))
            tags = source.get('tags', [])

            feats = extract_features(raw_msg, status_code, http_method, tags)

            doc_data = {
                'doc_id': doc_id,
                'index_name': index_name,
                'uri_length': feats[0],
                'special_char_count': feats[1],
                'special_char_ratio': feats[2],
                'digit_count': feats[3],
                'status_code': feats[4],
                'is_post': feats[5],
                'has_xss_tag': feats[6],
                'has_sqli_tag': feats[7],
                'has_brute_tag': feats[8],
                'has_csrf_tag': feats[9],
                'tags': tags,
                'message_sample': str(raw_msg)[:70]
            }

            all_docs.append(doc_data)

            if not any(tag in attack_tags for tag in tags):
                clean_docs.append(doc_data)

        df_all = pd.DataFrame(all_docs)
        df_clean = pd.DataFrame(clean_docs) if clean_docs else df_all

        feature_cols = [
            'uri_length', 'special_char_count', 'special_char_ratio',
            'digit_count', 'status_code', 'is_post',
            'has_xss_tag', 'has_sqli_tag', 'has_brute_tag', 'has_csrf_tag'
        ]

        # Guard: IsolationForest needs at least a couple of clean samples to train on
        if len(df_clean) < 2:
            print("[-] Not enough clean (untagged) logs to train a baseline. Generate more normal traffic first.")
            return

        model = IsolationForest(contamination=0.10, random_state=42)
        model.fit(df_clean[feature_cols])

        df_all['anomaly_prediction'] = model.predict(df_all[feature_cols])
        df_all['anomaly_score'] = model.decision_function(df_all[feature_cols])
        df_all['is_anomaly'] = df_all['anomaly_prediction'] == -1

        print(f"\n--- Model Results across Latest Web Logs (Trained on {len(df_clean)} Clean Logs) ---")
        print(df_all[['message_sample', 'uri_length', 'special_char_count', 'is_anomaly', 'anomaly_score']].head(12))

        print("\n[+] Updating Elasticsearch documents with AI fields...")
        actions = []
        for idx, row in df_all.iterrows():
            actions.append({
                "_op_type": "update",
                "_index": row['index_name'],
                "_id": row['doc_id'],
                "doc": {
                    "ai_detected_anomaly": bool(row['is_anomaly']),
                    "ai_anomaly_score": float(row['anomaly_score'])
                }
            })

        success, errors = helpers.bulk(es, actions, raise_on_error=False)

        if errors:
            print(f"[!] {len(errors)} documents failed to update:")
            for err in errors[:5]:
                print(f"    {err}")

        anomalies_count = df_all['is_anomaly'].sum()
        print(f"[✔] Successfully updated {success} documents in Elasticsearch!")
        print(f"[!] Total HTTP Web Logs Evaluated: {len(df_all)} | Total AI Anomalies Flagged: {anomalies_count}")

    except Exception as e:
        print(f"[-] Error during AI execution: {e}")

if __name__ == "__main__":
    run_ai_detection()
