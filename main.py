import os
import paramiko
import hashlib
import base64
import csv
import io
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

# Columns to exclude from the final upload
COLUMNS_TO_EXCLUDE = [
    'ad_exclude_override',
    'advertise_exclude',
    'margin',
    'margin_percentage',
    'status',
    'tax'
]

# Bing Shopping preferred column order (similar to Google but adjusted for Bing)
BING_COLUMN_ORDER = [
    'id', 'item_group_id', 'title', 'description', 'brand', 'link', 'image_link',
    'additional_image_link', 'product_type', 'google_product_category', 'sale_price',
    'sale_price_effective_date', 'price', 'shipping', 'mpn', 'gtin',
    'condition', 'availability', 'availability_date', 'shipping_weight',
    'age_group', 'gender', 'size', 'color', 'custom_label_0', 'custom_label_1',
    'custom_label_2', 'custom_label_3', 'custom_label_4', 'identifier_exists',
    'adwords_redirect', 'distressed', 'excluded_destination', 'link_redirect',
    'return_policy_label'
]


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


def normalize_column_name(col):
    col = col.strip().lower()
    col = col.replace(' ', '_')
    return col

SPECIAL_MAPPINGS = {
    'weight': 'shipping_weight'
}

def transform_tsv_headers(tsv_data):
    """Transform TSV headers dynamically; keep all original columns, normalize names, and preserve data."""
    try:
        logger.info("Transforming TSV headers dynamically...")

        # Decode bytes if needed
        if isinstance(tsv_data, bytes):
            tsv_data = tsv_data.decode('utf-8')

        # Read as TSV (tab-delimited from source)
        tsv_reader = csv.DictReader(io.StringIO(tsv_data), delimiter='\t')
        original_headers = tsv_reader.fieldnames or []
        logger.info(f"Original headers: {original_headers}")

        # Normalize and remap columns automatically
        dynamic_columns = []
        for source_col in original_headers:
            normalized = normalize_column_name(source_col)
            target_col = SPECIAL_MAPPINGS.get(normalized, normalized)
            if target_col not in COLUMNS_TO_EXCLUDE:
                dynamic_columns.append(target_col)

        # Keep standard order first, then add any new ones
        ordered_columns = [c for c in BING_COLUMN_ORDER if c in dynamic_columns]
        remaining_columns = [c for c in dynamic_columns if c not in ordered_columns]
        final_columns = ordered_columns + remaining_columns

        # Log any unexpected new columns
        new_columns = [col for col in remaining_columns if col not in BING_COLUMN_ORDER]
        if new_columns:
            logger.info(f"🆕 Detected new columns not in default order: {new_columns}")

        output = io.StringIO()
        # Write as TSV (tab-delimited) with no quoting
        tsv_writer = csv.DictWriter(
            output, 
            fieldnames=final_columns, 
            delimiter='\t', 
            quoting=csv.QUOTE_NONE, 
            escapechar='\\'
        )
        tsv_writer.writeheader()

        rows_processed = 0
        for row in tsv_reader:
            new_row = {}
            for source_col, value in row.items():
                normalized = normalize_column_name(source_col)
                target_col = SPECIAL_MAPPINGS.get(normalized, normalized)
                if target_col not in COLUMNS_TO_EXCLUDE:
                    # Remove any tab characters from field values to prevent column misalignment
                    if value:
                        value = value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
                    new_row[target_col] = value

            # Only keep columns that actually exist in this row
            filtered_row = {col: new_row[col] for col in new_row if col in final_columns}
            tsv_writer.writerow(filtered_row)
            rows_processed += 1

            if rows_processed % 1000 == 0:
                logger.info(f"Processed {rows_processed} rows...")

        transformed_tsv = output.getvalue()
        output.close()

        logger.info(
            f"TSV transformed successfully! Processed {rows_processed:,} rows "
            f"and retained {len(final_columns)} columns."
        )

        return transformed_tsv, rows_processed

    except Exception as e:
        logger.error(f"Error transforming TSV: {e}")
        raise


def download_from_source():
    """Download TSV from source FTP server in chunks"""
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

        logger.info("Connected to source server!")
        sftp = ssh.open_sftp()
        logger.info("SFTP connection opened successfully")

        logger.info(f"Attempting to open file: {SOURCE_CONFIG['filename']}")
        
        # Get file size
        file_stats = sftp.stat(SOURCE_CONFIG['filename'])
        file_size = file_stats.st_size
        logger.info(f"File size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
        
        # Read the file in chunks
        logger.info("Starting to read file content in chunks...")
        start_time = time.time()
        
        remote_file = sftp.open(SOURCE_CONFIG['filename'], 'r')
        
        # Read in 10MB chunks to avoid memory issues
        chunk_size = 10 * 1024 * 1024  # 10 MB
        chunks = []
        bytes_read = 0
        
        while True:
            chunk = remote_file.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            logger.info(f"Read {bytes_read:,} / {file_size:,} bytes ({bytes_read/file_size*100:.1f}%)")
        
        remote_file.close()
        
        # Combine chunks
        logger.info("Combining chunks...")
        tsv_data = b''.join(chunks)
        
        download_time = time.time() - start_time
        logger.info(f"Downloaded {len(tsv_data):,} bytes in {download_time:.2f} seconds")

        return tsv_data

    except Exception as e:
        logger.error(f"Error downloading from source: {e}")
        raise
    finally:
        if sftp:
            sftp.close()
            logger.info("SFTP connection closed")
        if ssh:
            ssh.close()
            logger.info("SSH connection closed")


def upload_to_microsoft(tsv_data):
    """Upload TSV to Microsoft Bing SFTP"""
    ssh = None
    sftp = None

    try:
        logger.info(f"Connecting to Microsoft server {BING_CONFIG['sftp_server']}:{BING_CONFIG['sftp_port']}...")

        ssh = paramiko.SSHClient()

        class FingerprintPolicy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                expected_fingerprint = BING_CONFIG['fingerprint']
                key_bytes = key.asbytes()
                fingerprint = hashlib.sha256(key_bytes).digest()
                actual_fingerprint = f"SHA256:{base64.b64encode(fingerprint).decode()}"

                if actual_fingerprint != expected_fingerprint:
                    raise Exception(f"Host key verification failed!")
                logger.info("Host key verification passed!")

        ssh.set_missing_host_key_policy(FingerprintPolicy())

        ssh.connect(
            hostname=BING_CONFIG['sftp_server'],
            port=BING_CONFIG['sftp_port'],
            username=BING_CONFIG['username'],
            password=BING_CONFIG['password'],
            timeout=30
        )

        logger.info("Connected to Microsoft server!")
        sftp = ssh.open_sftp()
        logger.info("SFTP connection to Microsoft opened successfully")

        filename = "tsi_thrive_bing_feed.txt"
        logger.info(f"Preparing to upload file: {filename}")
        logger.info(f"Upload file size: {len(tsv_data):,} bytes ({len(tsv_data) / 1024 / 1024:.2f} MB)")
        
        start_time = time.time()

        logger.info("Opening remote file for writing...")
        with sftp.open(filename, 'w') as f:
            logger.info("Writing data to remote file...")
            f.write(tsv_data)
            logger.info("Data written successfully")

        upload_time = time.time() - start_time
        logger.info(f"Successfully uploaded {filename} to Microsoft in {upload_time:.2f} seconds!")

        return upload_time

    except Exception as e:
        logger.error(f"Microsoft upload error: {e}")
        raise
    finally:
        if sftp:
            sftp.close()
            logger.info("SFTP connection to Microsoft closed")
        if ssh:
            ssh.close()
            logger.info("SSH connection to Microsoft closed")


def sync_feed():
    """Main function to sync the feed"""
    pst = pytz.timezone('America/Los_Angeles')
    pst_time = datetime.now(pst)
    timestamp = pst_time.strftime("%Y-%m-%d %H:%M:%S PST")
    
    try:
        logger.info("=== Starting Bing Feed Sync ===")
        
        # Download from source
        tsv_data = download_from_source()
        
        # Transform TSV headers
        transformed_tsv, rows_processed = transform_tsv_headers(tsv_data)
        
        # Upload to Microsoft
        upload_time = upload_to_microsoft(transformed_tsv)
        
        # Send success notification
        send_slack_success_message(timestamp, len(transformed_tsv), upload_time, rows_processed)
        
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
