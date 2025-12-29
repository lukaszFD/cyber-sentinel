db = db.getSiblingDB('threat_data_lake');
db.createCollection('virustotal_raw');
db.virustotal_raw.createIndex({ "resource": 1 }, { unique: true });
db.virustotal_raw.createIndex({ "scan_date": -1 });

print('MongoDB Threat Data Lake initialized successfully.');