// Switch to the target database for Cyber Sentinel telemetry
db = db.getSiblingDB('threat_data_lake');

const collectionName = 'threat_data_raw';
const collections = db.getCollectionNames();

// Check if the collection exists to prevent unnecessary creation steps
if (!collections.includes(collectionName)) {
    print('Collection ' + collectionName + ' does not exist. Creating...');
    db.createCollection(collectionName);
} else {
    print('Collection ' + collectionName + ' already exists. Skipping creation.');
}

// Create a compound index for efficient searching by resource and latest scan date
// resource: 1 (IP, FQDN, or Hash)
// scan_date: -1 (Descending order to find the most recent scan quickly)
db.threat_data_raw.createIndex({ "resource": 1, "scan_date": -1 });

// Create an index for the source provider to speed up filtered queries 
// (e.g., finding all reports specifically from VirusTotal or ThreatFox)
db.threat_data_raw.createIndex({ "source_provider": 1 });

print('MongoDB Threat Data Lake initialization completed.');