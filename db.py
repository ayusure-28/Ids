import mysql.connector
from mysql.connector import Error

# --- Database Connection ---
def create_db_connection():
    """Creates and returns a connection to the MySQL database."""
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='Aaha@143', # <-- REMEMBER TO CHANGE THIS
            database='idps_db'
        )
        return connection
    except Error as e:
        print(f"The error '{e}' occurred")
        return None

# --- Alert Logging ---
def log_alert(alert_type, src_ip, dst_ip, protocol, details):
    """Logs a new alert into the database."""
    if is_ip_blocked(src_ip):
        print(f"Alert from already-blocked IP {src_ip} suppressed.")
        return

    connection = create_db_connection()
    if connection is None: return
    
    cursor = connection.cursor()
    query = """
    INSERT INTO alerts (alert_type, source_ip, dest_ip, protocol, details) 
    VALUES (%s, %s, %s, %s, %s)
    """
    try:
        cursor.execute(query, (alert_type, src_ip, dst_ip, protocol, details))
        connection.commit()
        print(f"Alert logged successfully for {src_ip}")
    except Error as e:
        print(f"Failed to insert alert: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_alerts():
    """Fetches the 20 most recent alerts from the database."""
    connection = create_db_connection()
    if connection is None: return []

    cursor = connection.cursor(dictionary=True)
    query = "SELECT id, timestamp, alert_type, source_ip, dest_ip, protocol FROM alerts ORDER BY timestamp DESC LIMIT 20"
    try:
        cursor.execute(query)
        records = cursor.fetchall()
        for record in records:
            if 'timestamp' in record and record['timestamp']:
                record['timestamp'] = record['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        return records
    except Error as e:
        print(f"Failed to read alerts: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_alert_stats():
    """Fetches a count of alerts grouped by type. (Used for other potential graphs)"""
    connection = create_db_connection()
    if connection is None: return []
        
    cursor = connection.cursor(dictionary=True)
    query = "SELECT alert_type, COUNT(*) as count FROM alerts GROUP BY alert_type"
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except Error as e:
        print(f"Failed to read stats: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# --- FUNCTION FOR LINE GRAPH (UPDATED) ---
def get_alerts_over_time():
    """Fetches a count of alerts grouped by minute for the last 30 minutes."""
    connection = create_db_connection()
    if connection is None: return []
        
    cursor = connection.cursor(dictionary=True)
    # Get alerts per minute for the last 30 minutes
    query = """
    SELECT 
        DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') as time_minute, 
        COUNT(*) as count 
    FROM alerts 
    WHERE timestamp > NOW() - INTERVAL 30 MINUTE 
    GROUP BY time_minute 
    ORDER BY time_minute;
    """
    try:
        cursor.execute(query)
        records = cursor.fetchall()
        return records
    except Error as e:
        print(f"Failed to read time-series stats: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
# -----------------------------------

# --- BLOCKING FUNCTIONS ---

def block_ip(ip_address, reason="Manual Block"):
    """Adds an IP to the blocklist."""
    connection = create_db_connection()
    if connection is None: return False
    
    cursor = connection.cursor()
    query = "INSERT IGNORE INTO blocked_ips (ip_address, reason) VALUES (%s, %s)"
    try:
        cursor.execute(query, (ip_address, reason))
        connection.commit()
        print(f"Successfully blocked IP: {ip_address}")
        return True
    except Error as e:
        print(f"Failed to block IP: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_blocked_ips():
    """Fetches all blocked IPs from the database."""
    connection = create_db_connection()
    if connection is None: return []

    cursor = connection.cursor(dictionary=True)
    query = "SELECT ip_address, timestamp, reason FROM blocked_ips ORDER BY timestamp DESC"
    try:
        cursor.execute(query)
        records = cursor.fetchall()
        for record in records:
            if 'timestamp' in record and record['timestamp']:
                record['timestamp'] = record['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        return records
    except Error as e:
        print(f"Failed to read blocked IPs: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def is_ip_blocked(ip_address):
    """Checks if a given IP is in the blocklist."""
    connection = create_db_connection()
    if connection is None: return False
    
    cursor = connection.cursor(dictionary=True)
    query = "SELECT 1 FROM blocked_ips WHERE ip_address = %s LIMIT 1"
    try:
        cursor.execute(query, (ip_address,))
        record = cursor.fetchone()
        return record is not None
    except Error as e:
        print(f"Failed to check IP: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def unblock_ip(ip_address):
    """Removes an IP from the blocklist."""
    connection = create_db_connection()
    if connection is None: return False
    
    cursor = connection.cursor()
    query = "DELETE FROM blocked_ips WHERE ip_address = %s"
    try:
        cursor.execute(query, (ip_address,))
        connection.commit()
        if cursor.rowcount > 0:
            print(f"Successfully unblocked IP: {ip_address}")
            return True
        else:
            print(f"IP not found in blocklist: {ip_address}")
            return False
    except Error as e:
        print(f"Failed to unblock IP: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()