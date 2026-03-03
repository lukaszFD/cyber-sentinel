// Switch to the target database
db = db.getSiblingDB('threat_data_lake');

// Check if collection already exists before creating
const collectionName = 'virustotal_raw';
const collections = db.getCollectionNames();

if (!collections.includes(collectionName)) {
    print('Collection ' + collectionName + ' does not exist. Creating...');
    db.createCollection(collectionName);
} else {
    print('Collection ' + collectionName + ' already exists. Skipping creation.');
}

// Indexes in MongoDB are idempotent by default (createIndex only creates if not exists)
db.virustotal_raw.createIndex({ "resource": 1 }, { unique: true });
db.virustotal_raw.createIndex({ "scan_date": -1 });

print('MongoDB Threat Data Lake initialization check completed successfully.');