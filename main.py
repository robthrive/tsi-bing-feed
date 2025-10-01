import os
import paramiko
import hashlib
import base64
import logging
from datetime import datetime
import pytz
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from environment variables
SOURCE_CONFIG = {
    'hostname': os.getenv('SOURCE_HOSTNAME'),
    'port': int(os.getenv('SOURCE_PORT', 22)),
    'username': os.getenv('SOURCE_USERNAME'),
    'password': os.getenv('SOURCE_PASSWORD'),
    'filename': os.getenv('SOURCE_FILENAME')
}

BING_CONFIG = {
    'sftp_server': os.getenv('BING_SFTP_SERVER'),
    'sftp_port': int(os.getenv('BING_SFTP_PORT', 19321)),
    'username': os.getenv('BING_SFTP_USERNAME'),
    'password': os.getenv('BING_SFTP_PASSWORD'),
    'fingerprint': os.getenv('BING_FINGERPRINT')
}

# Slack configuration
SLACK_TOKEN = os.getenv('SLACK_BOT_TOKEN')
slack_client = WebClient(token=SLACK_TOKEN) if SLACK_TOKEN else None

# Channel for notifications
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL', '#internal-tsi-feed-updates')


def count_csv_rows(csv_data):
    """Count the number of rows in CSV data"""
    try:
        import csv
        import io
        
        if isinstance(csv_data, bytes):
            csv_data = csv_data.decode('utf-8')
        
        csv_reader = csv.reader(io.StringIO(csv_data))
        rows = list(csv_reader)
        
        # Subtract 1 for header row if it exists
        row_count = len(rows) - 1 if len(rows) > 0 else 0
        
        logger.info(f"📊 CSV contains {row_count:,} product rows")
        return max(0, row_count)  # Don't return negative numbers
        
    except Exception as e:
        logger.warning(f"Could not count CSV rows: {e}")
        return 0


def send_slack_success_message(timestamp, file_size, upload_time, rows_processed):
    """Send success message to Slack channel"""
    if not slack_client:
        logger.warning("Slack client not configured")
        return
    
    try:
        message = (
            f"✅ *Microsoft Bing Feed Updated Successfully*\n\n"
            f"📅 *Timestamp:* {timestamp}\n"
            f"📊 *File Size:* {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)\n"
            f"📦 *Products:* {rows_processed:,} items processed\n"
            f"⏱️ *Upload Time:* {upload_time:.2f} seconds\n"
            f"🎯 *Status:* Bing feed sync completed successfully"
        )
        
        slack_client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=message,
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        )
        logger.info("Success message sent to Slack")
    except SlackApiError as e:
        logger.error(f"Error sending success message to Slack: {e.response['error']}")


def send_slack_error_message(error_message, timestamp):
    """Send error message to Slack channel with @channel mention"""
    if not slack_client:
        logger.warning("Slack client not configured")
        return
    
    try:
        message = (
            f"🚨 <!channel> *Microsoft Bing Feed Update Failed*\n\n"
            f"📅 *Timestamp:* {timestamp}\n"
            f"❌ *Error:* {error_message}\n"
            f"🔧 *Action Required:* Please check the Bing feed sync process immediately"
        )
        
        slack_client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=message,
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        )
        logger.info("Error message sent to Slack with @channel")
    except SlackApiError as e:
        logger.error(f"Error sending error message to Slack: {e.response['error']}")


def download_from_source():
    """Download CSV from source FTP server"""
    ssh = None
    sftp = None

    try:
        logger.info(f"Connecting to source server {SOURCE_CONFIG['hostname']}:{SOURCE_CONFIG['port']}...")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh.connect(
            hostname=SOURCE_CONFIG['hostname'],
            port=SOURCE_CONFIG['port'],
            username=SOURCE_CONFIG['username'],
            password=SOURCE_CONFIG['password'],
            timeout=30
        )

        logger.info("✓ Connected to source server!")
        sftp = ssh.open_sftp()
        logger.info("✓ Source SFTP session opened!")

        # List files to see what's available
        logger.info("📋 Listing files on source server...")
        try:
            files = sftp.listdir('.')
            logger.info(f"📁 Found {len(files)} files in directory:")
            for file in files[:10]:  # Show first 10 files
                logger.info(f"   - {file}")
            if len(files) > 10:
                logger.info(f"   ... and {len(files) - 10} more files")
        except Exception as e:
            logger.warning(f"⚠️  Could not list directory: {e}")

        # Check if target file exists and get its size
        logger.info(f"📄 Checking file: {SOURCE_CONFIG['filename']}")
        try:
            file_stat = sftp.stat(SOURCE_CONFIG['filename'])
            file_size = file_stat.st_size
            logger.info(f"✓ File found! Size: {file_size:,} bytes ({file_size / 1024 / 1024:.1f} MB)")
        except Exception as e:
            logger.error(f"❌ Could not find file {SOURCE_CONFIG['filename']}: {e}")
            raise

        # Download the file with progress
        logger.info(f"⬇️  Starting download of {SOURCE_CONFIG['filename']}...")
        start_time = time.time()

        with sftp.open(SOURCE_CONFIG['filename'], 'r') as f:
            csv_data = f.read()

        download_time = time.time() - start_time
        logger.info(f"✅ Download completed! {len(csv_data):,} bytes in {download_time:.2f} seconds")
        
        if download_time > 0:
            speed = len(csv_data) / download_time / 1024 / 1024
            logger.info(f"🚀 Download speed: {speed:.2f} MB/s")

        # Show a sample of the data
        logger.info(f"📝 First 200 characters of CSV:")
        logger.info(f"   {csv_data[:200]}...")

        return csv_data

    except Exception as e:
        logger.error(f"❌ Error downloading from source: {e}")
        raise
    finally:
        if sftp:
            logger.info("🔒 Closing source SFTP connection...")
            sftp.close()
        if ssh:
            ssh.close()


def upload_to_microsoft(csv_data):
    """Upload CSV to Microsoft Bing SFTP"""
    ssh = None
    sftp = None

    try:
        logger.info(f"🔗 Connecting to Microsoft server {BING_CONFIG['sftp_server']}:{BING_CONFIG['sftp_port']}...")

        ssh = paramiko.SSHClient()

        class FingerprintPolicy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                expected_fingerprint = BING_CONFIG['fingerprint']
                key_bytes = key.asbytes()
                fingerprint = hashlib.sha256(key_bytes).digest()
                actual_fingerprint = f"SHA256:{base64.b64encode(fingerprint).decode()}"

                logger.info(f"🔐 Host key verification:")
                logger.info(f"   Expected: {expected_fingerprint}")
                logger.info(f"   Actual:   {actual_fingerprint}")

                if actual_fingerprint != expected_fingerprint:
                    raise Exception(f"Host key verification failed!")
                logger.info("✓ Host key verification passed!")

        ssh.set_missing_host_key_policy(FingerprintPolicy())

        ssh.connect(
            hostname=BING_CONFIG['sftp_server'],
            port=BING_CONFIG['sftp_port'],
            username=BING_CONFIG['username'],
            password=BING_CONFIG['password'],
            timeout=30
        )

        logger.info("✓ Connected to Microsoft server!")
        sftp = ssh.open_sftp()
        logger.info("✓ Microsoft SFTP session opened!")

        # List current directory to see what's there
        logger.info("📋 Listing Microsoft server directory...")
        try:
            files = sftp.listdir('.')
            logger.info(f"📁 Found {len(files)} files in Microsoft directory:")
            for file in files[:5]:  # Show first 5 files
                logger.info(f"   - {file}")
            if len(files) > 5:
                logger.info(f"   ... and {len(files) - 5} more files")
        except Exception as e:
            logger.warning(f"⚠️  Could not list Microsoft directory: {e}")

        filename = "tsi_thrive_bing_feed.csv"
        file_size = len(csv_data)
        
        logger.info(f"⬆️  Starting upload of {filename}...")
        logger.info(f"📊 Upload size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
        
        start_time = time.time()

        with sftp.open(filename, 'w') as f:
            f.write(csv_data)

        upload_time = time.time() - start_time
        logger.info(f"✅ Upload completed successfully!")
        logger.info(f"📈 Upload stats:")
        logger.info(f"   - File: {filename}")
        logger.info(f"   - Size: {file_size:,} bytes")
        logger.info(f"   - Time: {upload_time:.2f} seconds")
        
        if upload_time > 0:
            speed = file_size / upload_time / 1024 / 1024
            logger.info(f"   - Speed: {speed:.2f} MB/s")

        # Verify file exists and check size
        logger.info("🔍 Verifying uploaded file...")
        try:
            file_stat = sftp.stat(filename)
            uploaded_size = file_stat.st_size
            logger.info(f"✓ File verification successful!")
            logger.info(f"   - Expected size: {file_size:,} bytes")
            logger.info(f"   - Actual size: {uploaded_size:,} bytes")
            
            if uploaded_size != file_size:
                logger.warning(f"⚠️  Size mismatch! Expected {file_size}, got {uploaded_size}")
            else:
                logger.info(f"✓ File size matches perfectly!")
                
        except Exception as e:
            logger.error(f"❌ Could not verify uploaded file: {e}")
            # Don't raise here, upload might still be successful

        return upload_time

    except Exception as e:
        logger.error(f"❌ Microsoft upload error: {e}")
        raise
    finally:
        if sftp:
            logger.info("🔒 Closing Microsoft SFTP connection...")
            sftp.close()
        if ssh:
            ssh.close()


def sync_feed():
    """Main function to sync the feed"""
    # Get current time in PST/PDT timezone
    pst = pytz.timezone('America/Los_Angeles')
    pst_time = datetime.now(pst)
    timestamp = pst_time.strftime("%Y-%m-%d %H:%M:%S PST")
    
    try:
        logger.info("=== Starting Bing Feed Sync ===")
        
        # Download from source
        csv_data = download_from_source()
        
        # Count rows in CSV
        rows_processed = count_csv_rows(csv_data)
        
        # Upload to Microsoft
        upload_time = upload_to_microsoft(csv_data)
        
        # Send success notification
        send_slack_success_message(timestamp, len(csv_data), upload_time, rows_processed)
        
        logger.info("=== Bing feed sync completed successfully! ===")
        return True
        
    except Exception as e:
        error_message = str(e)
        logger.error(f"=== Bing feed sync failed: {error_message} ===")
        
        # Send error notification
        send_slack_error_message(error_message, timestamp)
        
        return False


def validate_config():
    """Validate that all required environment variables are set"""
    required_vars = [
        'SOURCE_HOSTNAME', 'SOURCE_USERNAME', 'SOURCE_PASSWORD', 'SOURCE_FILENAME',
        'BING_SFTP_SERVER', 'BING_SFTP_USERNAME', 'BING_SFTP_PASSWORD', 'BING_FINGERPRINT'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        return False
    
    logger.info("✓ All required environment variables are configured")
    return True


if __name__ == "__main__":
    logger.info("=== Microsoft Bing Feed Sync Worker Starting ===")
    
    # Validate configuration
    if not validate_config():
        logger.error("Configuration validation failed. Exiting.")
        exit(1)
    
    if SLACK_TOKEN:
        logger.info(f"✓ Slack notifications enabled for channel: {SLACK_CHANNEL}")
    else:
        logger.warning("⚠️ Slack notifications disabled (no SLACK_BOT_TOKEN)")
    
    # Run the sync once and exit
    logger.info("Running single sync...")
    success = sync_feed()

    if success:
        logger.info("✅ Sync completed successfully!")
    else:
        logger.error("❌ Sync failed!")
        exit(1)

    logger.info("=== Script completed ===")
