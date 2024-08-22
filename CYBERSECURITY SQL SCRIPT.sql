CREATE TABLE network_logs_2 (
    Linked_ID INT PRIMARY KEY,
    Threat_Type VARCHAR(255),
    Connection_Status VARCHAR(50),
    Severity_Level VARCHAR(50),
    Flagged BOOLEAN,
    Device_Type VARCHAR(255),
    Application VARCHAR(255),
    External_Internal_Flag VARCHAR(50),
    Service_Name VARCHAR(255),
    File_Hash VARCHAR(255),
    Linked_Events_ID INT,
    Data_Exfiltration_Flag BOOLEAN,
    Asset_Classification VARCHAR(255),
    Session_ID INT,
    TTL_Value INT,
    User_Behavior_Score FLOAT,
    Incident_Category VARCHAR(255),
    Cloud_Service_Info VARCHAR(255),
    IoC_Flag BOOLEAN
);

CREATE TABLE user_activity (
    ID SERIAL PRIMARY KEY,
    Activity_Count INTEGER,
    Suspicious_Activity BOOLEAN,
    Last_Activity_Timestamp TIMESTAMP,
    Browser TEXT,
	Number_of_Downloads INTEGER,
	Email_Sent INTEGER
);

CREATE TABLE network_logs (
    ID SERIAL PRIMARY KEY,
    Source_IP INT NOT NULL,
    Destination_IP INT NOT NULL,
    Protocol VARCHAR(10) NOT NULL,
    Timestamp TIMESTAMP NOT NULL,
    Traffic_Type VARCHAR(10) NOT NULL,
    Source_Port INTEGER NOT NULL,
    Destination_Port INTEGER NOT NULL,
    Data_Volume INTEGER NOT NULL,
    Packet_Size INTEGER NOT NULL,
    HTTP_Status_Code INTEGER NOT NULL,
    Firewall_Rule VARCHAR(20) NOT NULL,
    VPN_Status BOOLEAN NOT NULL,
    MFA_Status VARCHAR(10) NOT NULL,
    Credential_Used VARCHAR(50) NOT NULL,
    Data_Classification VARCHAR(20) NOT NULL,
    Encryption_Algorithm VARCHAR(50)
);


-- Viewing our data
SELECT *
FROM network_logs
LIMIT 5;

-- Identifying and Removing duplicates
SELECT source_ip, destination_ip, protocol, timestamp, COUNT(*)
FROM network_logs
GROUP BY source_ip, destination_ip,protocol, timestamp
HAVING COUNT(*) > 1;

SELECT linked_id, threat_type, severity_level, device_type,COUNT(*)
FROM network_logs_2
GROUP BY linked_id, threat_type, severity_level, device_type
HAVING COUNT(*) > 1;

--- Checking and deleting null values accross all columns dataset, to optimize this query sum can be used to replace count.
 SELECT 
    COUNT(CASE WHEN Source_IP IS NULL THEN 1 END) AS Source_IP_Missing,
    COUNT(CASE WHEN Destination_IP IS NULL THEN 1 END) AS Destination_IP_Missing,
    COUNT(CASE WHEN Protocol IS NULL THEN 1 END) AS Protocol_Missing,
    COUNT(CASE WHEN Timestamp IS NULL THEN 1 END) AS Timestamp_Missing,
	COUNT(CASE WHEN traffic_type IS NULL THEN 1 END) AS traffic_type_Missing,
	COUNT(CASE WHEN source_port IS NULL THEN 1 END) AS source_port_Missing,
	COUNT(CASE WHEN destination_port IS NULL THEN 1 END) AS destination_port_Missing,
	COUNT(CASE WHEN data_volume IS NULL THEN 1 END) AS data_volume_Missing,
	COUNT(CASE WHEN packet_size IS NULL THEN 1 END) AS packet_size_Missing,
	COUNT(CASE WHEN http_status_code IS NULL THEN 1 END) AS http_status_code_Missing,
	COUNT(CASE WHEN firewall_rule IS NULL THEN 1 END) AS firewall_rule_Missing,
	COUNT(CASE WHEN vpn_status IS NULL THEN 1 END) AS vpn_status_Missing,
	COUNT(CASE WHEN mfa_status IS NULL THEN 1 END) AS mfa_status_Missing,
	COUNT(CASE WHEN credential_used IS NULL THEN 1 END) AS credential_status_Missing,
	COUNT(CASE WHEN data_classification IS NULL THEN 1 END) AS data_classification_Missing,
    COUNT(CASE WHEN Encryption_Algorithm IS NULL THEN 1 END) AS Encryption_Algorithm_Missing
FROM 
    network_logs;

-- Investigate missing values
SELECT Protocol,COUNT(*) 
FROM network_logs 
WHERE Encryption_Algorithm IS NULL 
GROUP BY Protocol;

-- Set missing values as unknown
UPDATE network_logs 
SET Encryption_Algorithm = 'Unknown' 
WHERE Encryption_Algorithm IS NULL;

SELECT Encryption_Algorithm
FROM network_logs
WHERE Encryption_Algorithm = 'Unknown';

-- Simple Data Tranformation,Categorizing traffic based on its type
ALTER TABLE network_logs ADD COLUMN Traffic_Category VARCHAR(255);
UPDATE network_logs 
SET Traffic_Category = CASE WHEN Traffic_Type = 'Inbound' THEN 'Incoming' ELSE 'Outgoing' END;

-- we would do the same for network_logs_2 table, Categorizing threats based on severity
ALTER TABLE network_logs_2 ADD COLUMN Severity_Category VARCHAR(255);
UPDATE network_logs_2 SET Severity_Category = CASE 
    WHEN severity_level = 'Low' THEN 'Low Risk'
    WHEN severity_level = 'Medium' THEN 'Medium Risk'
    ELSE 'High Risk' 
END;

-- Some data manipulation, Count the number of high-risk threats
SELECT COUNT(*) FROM network_logs_2 WHERE Severity_Category = 'High Risk';
SELECT COUNT(*) FROM network_logs_2 WHERE Severity_Category = 'Low Risk';
SELECT COUNT(*) FROM network_logs_2 WHERE Severity_Category = 'Medium Risk';

-- Query optimization
SELECT 
    SUM(CASE WHEN Severity_Category = 'High Risk' THEN 1 ELSE 0 END) as High_Risk_Count,
    SUM(CASE WHEN Severity_Category = 'Low Risk' THEN 1 ELSE 0 END) as Low_Risk_Count,
    SUM(CASE WHEN Severity_Category = 'Medium Risk' THEN 1 ELSE 0 END) as Medium_Risk_Count
FROM network_logs_2;

-- Identify the most frequent device used to log in
SELECT Device_Type, COUNT(*) as device_Count 
FROM network_logs_2 
GROUP BY Device_Type 
ORDER BY device_Count
DESC;

-- Identify the type of traffic with the most data volume
SELECT Traffic_Category, SUM(Data_Volume) as Total_Data_Volume 
FROM network_logs
GROUP BY Traffic_Category 
ORDER BY Total_Data_Volume 
DESC;

-- Identify the correlation between traffic type and data volume
SELECT Traffic_Type, AVG(Data_Volume) as Average_Data_Volume 
FROM network_logs 
GROUP BY Traffic_Type;

-- Identify how many threats were flagged and were critical
SELECT COUNT(*)
FROM network_logs_2 
WHERE Flagged = TRUE AND Asset_Classification = 'Critical';

-- Determine the encryption algorithms used for sensitive data
SELECT DISTINCT Encryption_Algorithm
FROM network_logs
WHERE Data_Classification = 'Highly Confidential' OR Data_Classification = 'Confidential';

-- Count of Failed attempts
SELECT 
    Source_IP, 
    COUNT(ID) AS Failed_Attempts, 
    GROUP_CONCAT(DISTINCT VPN_Status ORDER BY VPN_Status ASC) AS VPN_Status_Variants, 
    GROUP_CONCAT(DISTINCT Firewall_Rule ORDER BY Firewall_Rule ASC) AS Firewall_Rules, 
    GROUP_CONCAT(DISTINCT Data_Classification ORDER BY Data_Classification ASC) AS Data_Classification_Types
FROM network_logs
WHERE MFA_Status = 'Failed'
GROUP BY Source_IP
ORDER BY Failed_Attempts DESC;

-- joining both tables
SELECT A.*, B.Threat_Type, B.Severity_Level
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
WHERE B.Severity_Level = 'High' OR B.Severity_Level = 'Critical';

-- count of logs where severity level is high or critical
SELECT COUNT(*) 
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
WHERE B.Severity_Level IN ('High', 'Critical');


-- Investigating the known types of threats
SELECT * 
FROM network_logs_2
WHERE Threat_Type IN ('DDoS', 'Malware')
ORDER BY Severity_Level DESC;

-- Identifying suspicious activity
SELECT * 
FROM user_activity
WHERE Suspicious_Activity = '1';

-- Monitoring data exfilitation and classification
SELECT A.*, B.Data_Exfiltration_Flag 
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
WHERE A.Data_Classification IN ('Confidential', 'Highly Confidential') AND B.Data_Exfiltration_Flag = '1';

-- Trend of different severity levels over time
SELECT 
    A.Severity_Level, 
    to_char(B.Timestamp, 'YYYY-MM') as Month, 
    COUNT(*) as Event_Count
FROM network_logs_2 A
JOIN network_logs B ON B.ID = A.Linked_ID
GROUP BY A.Severity_Level, to_char(B.Timestamp, 'YYYY-MM')
ORDER BY Month ASC, Event_Count DESC;

-- Count of failed MFA attempts within a time window
SELECT Source_IP, COUNT(ID) as Failed_Attempts
FROM network_logs
ork_logs
WHERE MFA_Status = 'Failed' AND Timestamp BETWEEN '2023-01-01' AND '2023-02-01'
GROUP BY Source_IP
ORDER BY Failed_Attempts DESC;

-- High and critical issues that are allowed
SELECT *
FROM network_logs_2
WHERE (Severity_Level = 'High' OR Severity_Level = 'Critical') AND Connection_Status = 'Allowed';

-- Treats with high user behaviour score
SELECT A.Threat_Type, A.User_Behavior_Score
FROM network_logs_2 A
JOIN user_activity B ON A.Linked_ID = B.ID
WHERE A.User_Behavior_Score > 0.8
ORDER BY A.User_Behavior_Score DESC;

-- Users with Multiple Downloads and High Activity
SELECT * FROM user_activity
WHERE Number_of_Downloads > 5 AND Activity_Count > 50;

-- Data Leakage: Critical Assets with Data Exfiltration
SELECT A.Linked_ID, A.Data_Exfiltration_Flag, B.Data_Classification
FROM network_logs_2 A
JOIN network_logs B ON A.Linked_ID = B.ID
WHERE A.Data_Exfiltration_Flag = '1'
AND B.Data_Classification = 'Highly Confidential';

-- Count of Critical and High-Severity Events Over Time. To understand how the rate of severe threats changes over time.
SELECT DATE_TRUNC('month', A.Timestamp) AS Month, COUNT(*) as Critical_High_Count
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
WHERE B.Severity_Level IN ('High', 'Critical')
GROUP BY DATE_TRUNC('month', A.Timestamp)
ORDER BY Month;

-- Types of Attacks, to show the distribution of different types of threats
SELECT B.Threat_Type, COUNT(*) as Threat_Count
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
GROUP BY B.Threat_Type
ORDER BY Threat_Count DESC;

-- Number of Inbound Vs Outbound Traffic, it gives us an an idea of how much traffic is incoming vs outgoing, 
-- which is often useful to understand the attack surface.
SELECT A.Traffic_Type, COUNT(*) as Traffic_Count
FROM network_logs A
GROUP BY A.Traffic_Type
ORDER BY Traffic_Count DESC;

-- Firewall Rule Effectiveness
-- Assess the effectiveness of your firewall rules by monitoring how often each rule is triggered.
SELECT A.Firewall_Rule, COUNT(*) as Rule_Trigger_Count
FROM network_logs A
GROUP BY A.Firewall_Rule
ORDER BY Rule_Trigger_Count DESC;


--- Average User Behavior Score for Different Threat Types
-- To help in identifying whether certain kinds of threats are correlated with anomalous user behavior.
SELECT B.Threat_Type, AVG(B.User_Behavior_Score) as Avg_User_Behavior_Score
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
JOIN user_activity C ON A.ID = C.ID
GROUP BY B.Threat_Type
ORDER BY Avg_User_Behavior_Score DESC;

-- MFA and VPN Status for High or Critical Threats
SELECT A.MFA_Status, A.VPN_Status, COUNT(*) as Threat_Count
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
WHERE B.Severity_Level IN ('High', 'Critical')
GROUP BY A.MFA_Status, A.VPN_Status
ORDER BY Threat_Count DESC;

-- Frequency of Different Encryption Algorithms for Confidential Data
-- To help us find if highly sensitive data is being encrypted with strong algorithms.
SELECT A.Encryption_Algorithm, COUNT(*) as Frequency
FROM network_logs A
WHERE A.Data_Classification IN ('Confidential', 'Highly Confidential')
GROUP BY A.Encryption_Algorithm
ORDER BY Frequency DESC;

-- Trend of High or Critical Threats by Protocol and Month
DELIMITER $$

CREATE PROCEDURE fetch_critical_high_trends()
BEGIN
	-- Create a temporary table to store the results
	CREATE TEMPORARY TABLE IF NOT EXISTS temp_trends (
		Month TIMESTAMP,
		Protocol VARCHAR(255),
		Critical_High_Count INT
	);

   -- Insert the results into the temporary table
	INSERT INTO temp_trends (Month, Protocol, Critical_High_Count)
	SELECT DATE_FORMAT(A.Timestamp, '%Y-%m-01') AS Month,  -- Truncate to the first day of the month
			A.Protocol AS Protocol,
			COUNT(*) AS Critical_High_Count
	FROM network_logs A
	JOIN network_logs_2 B ON A.ID = B.Linked_ID
	WHERE B.Severity_Level IN ('High', 'Critical')
	GROUP BY DATE_FORMAT(A.Timestamp, '%Y-%m-01'), A.Protocol
	ORDER BY Month, Critical_High_Count DESC;

	-- Select from the temporary table
	SELECT * FROM temp_trends;

	-- Drop the temporary table
	DROP TEMPORARY TABLE IF EXISTS temp_trends;
END$$

DELIMITER ;


DROP PROCEDURE IF EXISTS fetch_critical_high_trends;

SELECT * FROM fetch_critical_high_trends;

-- MFA and VPN Status for High or Critical Threats
DELIMITER $$

CREATE PROCEDURE fetch_high_critical_MFA_VPN()
BEGIN
  SELECT A.ID, 
         A.MFA_Status, 
         A.VPN_Status
  FROM network_logs A
  JOIN network_logs_2 B ON A.ID = B.Linked_ID
  WHERE B.Severity_Level IN ('High', 'Critical');
END$$
DELIMITER ;


SELECT * FROM fetch_high_critical_MFA_VPN;

-- Frequency of Different Encryption Algorithms for Confidential Data
DELIMITER $$

CREATE PROCEDURE fetch_encryption_frequency()
BEGIN
  SELECT n.Encryption_Algorithm, 
         COUNT(*) AS Frequency
  FROM network_logs AS n
  WHERE n.Data_Classification = 'Confidential'
  GROUP BY n.Encryption_Algorithm;
END$$
DELIMITER ;

SELECT * FROM fetch_encryption_frequency;