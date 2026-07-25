import string
from elasticsearch import Elasticsearch, helpers
import pandas as pd
from sklearn.ensemble import IsolationForest

es = Elasticsearch(["http://localhost:9200"])

def extract_features(raw_text, status_code, method):
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

    return [uri_length, special_char_count, special_char_ratio, digit_count, status, is_post]

def run_ai_detection():
    # Query broader HTTP web events specifically matching web paths or DVWA
    query = {
        "query": {
            "bool": {
                "should": [
                    {"wildcard": {"message": "*/vulnerabilities/*"}},
                    {"wildcard": {"message": "*GET *"}},
                    {"wildcard": {"message": "*POST *"}},
                    {"exists": {"field": "request_path"}}
                ],
                "minimum_should_match": 1,
                "must_not": [
                    {"wildcard": {"message": "*AbstractManagedProcess*"}},
                    {"wildcard": {"message": "*plugins*"}}
                ]
            }
        },
        "size": 1000,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    
    try:
        response = es.search(index="logstash-*", body=query)
        hits = response['hits']['hits']

        if not hits:
            print("[-] No web access logs found in Elasticsearch.")
            return

        print(f"[+] Extracting features from {len(hits)} HTTP web logs...")
        
        processed_data = []
        for hit in hits:
            source = hit['_source']
            doc_id = hit['_id']
            index_name = hit['_index']
            
            raw_msg = source.get('request_path') or source.get('message') or source.get('event', {}).get('original', '')
            status_code = source.get('response', source.get('http_status', 200))
            http_method = source.get('verb', source.get('http_method', 'GET'))
            
            feats = extract_features(raw_msg, status_code, http_method)
            
            processed_data.append({
                'doc_id': doc_id,
                'index_name': index_name,
                'uri_length': feats[0],
                'special_char_count': feats[1],
                'special_char_ratio': feats[2],
                'digit_count': feats[3],
                'status_code': feats[4],
                'is_post': feats[5],
                'message_sample': str(raw_msg)[:70]
            })

        df = pd.DataFrame(processed_data)
        feature_cols = ['uri_length', 'special_char_count', 'special_char_ratio', 'digit_count', 'status_code', 'is_post']
        
        model = IsolationForest(contamination=0.15, random_state=42)
        df['anomaly_prediction'] = model.fit_predict(df[feature_cols])
        df['anomaly_score'] = model.decision_function(df[feature_cols])
        df['is_anomaly'] = df['anomaly_prediction'] == -1
        
        print("\n--- Top Analyzed Logs (Latest First) ---")
        print(df[['message_sample', 'uri_length', 'special_char_count', 'is_anomaly', 'anomaly_score']].head(10))
        
        print("\n[+] Updating Elasticsearch documents with AI fields...")
        actions = []
        for idx, row in df.iterrows():
            actions.append({
                "_op_type": "update",
                "_index": row['index_name'],
                "_id": row['doc_id'],
                "doc": {
                    "ai_detected_anomaly": bool(row['is_anomaly']),
                    "ai_anomaly_score": float(row['anomaly_score'])
                }
            })
            
        success, _ = helpers.bulk(es, actions)
        
        anomalies_count = df['is_anomaly'].sum()
        print(f"[✔] Successfully updated {success} documents in Elasticsearch!")
        print(f"[!] Total Analyzed: {len(df)} | Web Anomalies Flagged: {anomalies_count}")
        
    except Exception as e:
        print(f"[-] Error during AI execution: {e}")

if __name__ == "__main__":
    run_ai_detection()
