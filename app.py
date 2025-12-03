#!/usr/bin/env python3
"""
Amazon Payment Processor - Streamlit App
Extracts payment details from Amazon emails and appends to Google Sheets
"""

import streamlit as st
import os
import re
import base64
import json
import time
import tempfile
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from io import StringIO, BytesIO
import warnings

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

warnings.filterwarnings("ignore")

# Configure Streamlit page
st.set_page_config(
    page_title="Amazon Payment Processor",
    page_icon="💰",
    layout="wide",
    initial_sidebar_state="expanded"
)

class AmazonPaymentProcessor:
    def __init__(self):
        self.gmail_service = None
        self.sheets_service = None
        
        # API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
        # Initialize logs in session state if not exists
        if 'logs' not in st.session_state:
            st.session_state.logs = []
        
        # Initialize config in session state if not exists
        if 'config' not in st.session_state:
            st.session_state.config = {
                'gmail': {
                    'sender': 'no-reply@amazon.com',
                    'search_term': 'Remittance Advice - MIMANSA INDUSTRIES PRIVATE LIMITED',
                    'days_back': 30,
                    'max_results': 1000
                },
                'sheet': {
                    'spreadsheet_id': '1TTCI9kL9N5z0aALyxIJztyh8dK-4xbkf3dLvCK8g1p4',
                    'sheet_range': 'amazon'
                }
            }
    
    def log(self, message: str, level: str = "INFO"):
        """Add log entry with timestamp to session state"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp, 
            "level": level.upper(), 
            "message": message
        }
        
        # Add to session state logs
        if 'logs' not in st.session_state:
            st.session_state.logs = []
        
        st.session_state.logs.append(log_entry)
        
        # Keep only last 100 logs to prevent memory issues
        if len(st.session_state.logs) > 100:
            st.session_state.logs = st.session_state.logs[-100:]
    
    def get_logs(self):
        """Get logs from session state"""
        return st.session_state.get('logs', [])
    
    def clear_logs(self):
        """Clear all logs"""
        st.session_state.logs = []
    
    def get_config(self):
        """Get configuration from session state"""
        return st.session_state.get('config', {
            'gmail': {
                'sender': 'no-reply@amazon.com',
                'search_term': 'Remittance Advice - MIMANSA INDUSTRIES PRIVATE LIMITED',
                'days_back': 30,
                'max_results': 1000
            },
            'sheet': {
                'spreadsheet_id': '1TTCI9kL9N5z0aALyxIJztyh8dK-4xbkf3dLvCK8g1p4',
                'sheet_range': 'amazon'
            }
        })
    
    def update_config(self, new_config: Dict):
        """Update configuration in session state"""
        st.session_state.config = new_config
    
    def authenticate_from_secrets(self, progress_bar, status_text):
        """Authenticate using Streamlit secrets with web-based OAuth flow"""
        try:
            self.log("Starting authentication process...", "INFO")
            status_text.text("Authenticating with Google APIs...")
            progress_bar.progress(10)
            
            # Check for existing token in session state
            if 'oauth_token' in st.session_state:
                try:
                    combined_scopes = list(set(self.gmail_scopes + self.sheets_scopes))
                    creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
                    if creds and creds.valid:
                        progress_bar.progress(50)
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful using cached token!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                    elif creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful after token refresh!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                except Exception as e:
                    self.log(f"Cached token invalid: {str(e)}", "WARNING")
            
            # Use Streamlit secrets for OAuth
            if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
                creds_data = json.loads(st.secrets["google"]["credentials_json"])
                combined_scopes = list(set(self.gmail_scopes + self.sheets_scopes))
                
                # Configure for web application
                flow = Flow.from_client_config(
                    client_config=creds_data,
                    scopes=combined_scopes,
                    redirect_uri=st.secrets.get("redirect_uri", "https://amazonpa.streamlit.app/")
                )
                
                # Generate authorization URL
                auth_url, _ = flow.authorization_url(prompt='consent')
                
                # Check for callback code
                query_params = st.query_params
                if "code" in query_params:
                    try:
                        code = query_params["code"]
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        
                        # Save credentials in session state
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        
                        progress_bar.progress(50)
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        
                        progress_bar.progress(100)
                        self.log("OAuth authentication successful!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        
                        # Clear the code from URL
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        self.log(f"OAuth authentication failed: {str(e)}", "ERROR")
                        st.error(f"Authentication failed: {str(e)}")
                        return False
                else:
                    # Show authorization link
                    st.markdown("### Google Authentication Required")
                    st.markdown(f"[Click here to authorize with Google]({auth_url})")
                    self.log("Waiting for user to authorize application", "INFO")
                    st.info("Click the link above to authorize, you'll be redirected back automatically")
                    st.stop()
            else:
                self.log("Google credentials missing in Streamlit secrets", "ERROR")
                st.error("Google credentials missing in Streamlit secrets")
                return False
                
        except Exception as e:
            self.log(f"Authentication failed: {str(e)}", "ERROR")
            st.error(f"Authentication failed: {str(e)}")
            return False
    
    def search_emails(self, config: Dict) -> List[Dict]:
        """Search for Amazon payment emails"""
        try:
            # Build search query
            query_parts = []
            
            if config['sender']:
                query_parts.append(f'from:"{config["sender"]}"')
            
            if config['search_term']:
                query_parts.append(f'"{config["search_term"]}"')
            
            # Add date filter
            start_date = datetime.now() - timedelta(days=config['days_back'])
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            
            query = " ".join(query_parts)
            self.log(f"Searching Gmail with query: {query}", "INFO")
            self.log(f"Looking for emails from last {config['days_back']} days", "INFO")
            
            # Execute search
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=config['max_results']
            ).execute()
            
            messages = result.get('messages', [])
            self.log(f"Gmail search returned {len(messages)} messages", "INFO")
            
            return messages
            
        except Exception as e:
            self.log(f"Email search failed: {str(e)}", "ERROR")
            return []
    
    def get_email_body(self, message_id: str) -> str:
        """Extract email body from message - handles both text and HTML formats"""
        try:
            message = self.gmail_service.users().messages().get(
                userId='me', id=message_id, format='full'
            ).execute()
            
            body = ""
            
            def decode_part(data):
                """Helper function to decode base64 data"""
                try:
                    return base64.urlsafe_b64decode(data).decode('utf-8')
                except Exception as e:
                    self.log(f"Failed to decode part: {str(e)}", "WARNING")
                    return ""
            
            def get_body_from_parts(parts, prefer_html=False):
                """Recursively extract body from message parts"""
                text_body = ""
                html_body = ""
                
                for part in parts:
                    mime_type = part.get('mimeType', '')
                    
                    # Handle nested multipart
                    if 'parts' in part:
                        nested_text, nested_html = get_body_from_parts(part['parts'], prefer_html)
                        if not text_body:
                            text_body = nested_text
                        if not html_body:
                            html_body = nested_html
                    
                    # Extract text/plain
                    elif mime_type == 'text/plain':
                        if 'data' in part.get('body', {}):
                            text_body = decode_part(part['body']['data'])
                    
                    # Extract text/html
                    elif mime_type == 'text/html':
                        if 'data' in part.get('body', {}):
                            html_body = decode_part(part['body']['data'])
                
                # Return HTML if prefer_html is True and HTML exists, otherwise return text
                if prefer_html and html_body:
                    return text_body, html_body
                return text_body, html_body
            
            if 'payload' in message:
                payload = message['payload']
                
                # Handle multipart messages
                if 'parts' in payload:
                    text_body, html_body = get_body_from_parts(payload['parts'])
                    # Prefer text/plain, but use HTML if text is not available
                    body = text_body if text_body else html_body
                else:
                    # Single part message
                    if 'body' in payload and 'data' in payload['body']:
                        body = decode_part(payload['body']['data'])
            
            # If we got HTML, try to convert it to plain text
            if body and '<html' in body.lower():
                try:
                    from html.parser import HTMLParser
                    
                    class HTMLToText(HTMLParser):
                        def __init__(self):
                            super().__init__()
                            self.text = []
                        
                        def handle_data(self, data):
                            self.text.append(data)
                        
                        def get_text(self):
                            return ''.join(self.text)
                    
                    parser = HTMLToText()
                    parser.feed(body)
                    plain_text = parser.get_text()
                    
                    # Only use parsed HTML if it has content
                    if plain_text.strip():
                        body = plain_text
                        
                except Exception as e:
                    self.log(f"Failed to parse HTML, using raw content: {str(e)}", "WARNING")
            
            if not body:
                self.log(f"No body content extracted for message {message_id}", "WARNING")
            else:
                self.log(f"Successfully extracted body of length {len(body)} for message {message_id}", "INFO")
            
            return body
            
        except Exception as e:
            self.log(f"Failed to get email body: {str(e)}", "ERROR")
            import traceback
            self.log(f"Traceback: {traceback.format_exc()}", "ERROR")
            return ""
    
    def extract_payment_data(self, email_body: str) -> Dict[str, Any]:
        """Extract payment details and table data from email body"""
        try:
            payment_data = {
                'payment_date': '',
                'payment_amount': '',
                'table_data': []
            }
            
            # Extract payment date
            payment_date_match = re.search(r'Payment date:(\d{2}-[A-Z]{3}-\d{4})', email_body, re.IGNORECASE)
            if payment_date_match:
                payment_data['payment_date'] = payment_date_match.group(1)
            
            # Extract payment amount
            payment_amount_match = re.search(r'Payment amount:([\d,]+\.\d{2})', email_body, re.IGNORECASE)
            if payment_amount_match:
                payment_data['payment_amount'] = payment_amount_match.group(1).replace(',', '')
            
            self.log(f"Found payment date: {payment_data['payment_date']}", "INFO")
            self.log(f"Found payment amount: {payment_data['payment_amount']}", "INFO")
            
            # Try multiple header patterns
            header_patterns = [
                r'__Invoice Number:Invoice Date:.*?Amount Remaining__',
                r'_+Invoice Number:Invoice Date:.*?Amount Remaining_+',
                r'Invoice Number:Invoice Date:.*?Amount Remaining',
                r'Invoice Number.*?Invoice Date.*?Invoice description.*?Amount Remaining'
            ]
            
            header_match = None
            for pattern in header_patterns:
                header_match = re.search(pattern, email_body, re.IGNORECASE | re.DOTALL)
                if header_match:
                    self.log(f"Found table header with pattern: {pattern[:50]}...", "INFO")
                    break
            
            if not header_match:
                # Debug: show what's around the expected header location
                self.log("No table header found. Searching for 'Invoice Number' to debug...", "WARNING")
                invoice_number_pos = email_body.find('Invoice Number')
                if invoice_number_pos != -1:
                    context = email_body[max(0, invoice_number_pos-50):invoice_number_pos+200]
                    self.log(f"Found 'Invoice Number' at position {invoice_number_pos}. Context: {repr(context)}", "INFO")
                return payment_data
            
            # Get content after the header
            table_start = header_match.end()
            table_content = email_body[table_start:].strip()
            
            self.log(f"Table content extracted, length: {len(table_content)}", "INFO")
            self.log(f"First 200 chars of table: {repr(table_content[:200])}", "INFO")
            
            # Split by lines
            lines = table_content.split('\n')
            self.log(f"Found {len(lines)} lines in table content", "INFO")
            
            # Pattern to match invoice rows
            for idx, line in enumerate(lines):
                line = line.strip()
                
                if not line:
                    continue
                
                self.log(f"Processing line {idx}: {repr(line[:100])}", "INFO")
                
                # Stop at certain markers
                if any(marker in line for marker in ['Payment made to:', 'Please do not reply', 
                                                    'Amazon Retail India', '©', 'unsubscribe']):
                    self.log(f"Stopping at marker line: {line[:50]}", "INFO")
                    break
                
                # Try to parse the line
                invoice_match = re.match(r'^([A-Z0-9-]+)(\d{2}-[A-Z]{3}-\d{4})(.+)$', line, re.IGNORECASE)
                
                if invoice_match:
                    invoice_number = invoice_match.group(1)
                    invoice_date = invoice_match.group(2)
                    remaining_data = invoice_match.group(3)
                    
                    self.log(f"Matched invoice: {invoice_number} | {invoice_date}", "INFO")
                    self.log(f"Remaining data: {repr(remaining_data[:100])}", "INFO")
                    
                    # Extract amounts from the end
                    amount_pattern = r'(\([\d,]+\.\d{2}\)|[\d,]+\.\d{2})'
                    amounts = re.findall(amount_pattern, remaining_data)
                    
                    self.log(f"Found {len(amounts)} amounts: {amounts}", "INFO")
                    
                    if len(amounts) >= 4:
                        # Get the last 4 amounts
                        invoice_amount = amounts[-4]
                        tds_amount = amounts[-3]
                        amount_paid = amounts[-2]
                        amount_remaining = amounts[-1]
                        
                        # Extract description
                        first_amount_pos = remaining_data.find(amounts[-4])
                        description = remaining_data[:first_amount_pos].strip()
                        
                        # Clean up amounts
                        def clean_amount(amt):
                            if amt.startswith('(') and amt.endswith(')'):
                                return '-' + amt[1:-1].replace(',', '')
                            return amt.replace(',', '')
                        
                        row_dict = {
                            'Invoice Number': invoice_number,
                            'Invoice Date': invoice_date,
                            'Invoice description': description,
                            'Invoice amount': clean_amount(invoice_amount),
                            'TDS Amount': clean_amount(tds_amount),
                            'Discount Taken': '',
                            'Amount Paid': clean_amount(amount_paid),
                            'Amount Remaining': clean_amount(amount_remaining)
                        }
                        
                        payment_data['table_data'].append(row_dict)
                        self.log(f"Successfully parsed row: {invoice_number} | {invoice_date} | {description[:30]}...", "INFO")
                    else:
                        self.log(f"Not enough amounts found (need 4, got {len(amounts)})", "WARNING")
                else:
                    self.log(f"Line did not match invoice pattern", "INFO")
            
            self.log(f"Extracted {len(payment_data['table_data'])} rows from table", "INFO")
            return payment_data
            
        except Exception as e:
            self.log(f"Failed to extract payment data: {str(e)}", "ERROR")
            import traceback
            self.log(f"Traceback: {traceback.format_exc()}", "ERROR")
            return {'payment_date': '', 'payment_amount': '', 'table_data': []}
    
    def process_table_data(self, table_data: List[Dict], payment_date: str, payment_amount: str) -> pd.DataFrame:
        """Convert table data to DataFrame and add payment columns"""
        try:
            if not table_data:
                return pd.DataFrame()
            
            # Convert to DataFrame
            df = pd.DataFrame(table_data)
            
            # Add the two new columns
            df['Payment Date'] = payment_date
            df['Payment Amount'] = payment_amount
            
            self.log(f"Processed table data with shape: {df.shape}", "INFO")
            return df
            
        except Exception as e:
            self.log(f"Failed to process table data: {str(e)}", "ERROR")
            return pd.DataFrame()
    
    def append_to_sheet(self, df: pd.DataFrame, config: Dict):
        """Append DataFrame to Google Sheet"""
        try:
            if df.empty:
                self.log("No data to append", "WARNING")
                return False
            
            # Check if sheet has existing data to determine if we need headers
            try:
                result = self.sheets_service.spreadsheets().values().get(
                    spreadsheetId=config['spreadsheet_id'],
                    range=config['sheet_range']
                ).execute()
                
                values = result.get('values', [])
                include_headers = len(values) == 0
                
            except HttpError as e:
                # Range might be empty, include headers
                include_headers = True
            
            # Convert DataFrame to values
            if include_headers:
                values = [df.columns.tolist()] + df.fillna('').astype(str).values.tolist()
            else:
                values = df.fillna('').astype(str).values.tolist()
            
            if not values:
                self.log("No values to append", "WARNING")
                return False
            
            # Prepare the request body
            body = {
                'values': values
            }
            
            # Append data to the sheet
            if include_headers:
                # Use update for first time (with headers)
                result = self.sheets_service.spreadsheets().values().update(
                    spreadsheetId=config['spreadsheet_id'],
                    range=config['sheet_range'],
                    valueInputOption='USER_ENTERED',
                    body=body
                ).execute()
            else:
                # Use append for subsequent additions
                result = self.sheets_service.spreadsheets().values().append(
                    spreadsheetId=config['spreadsheet_id'],
                    range=config['sheet_range'],
                    valueInputOption='USER_ENTERED',
                    insertDataOption='INSERT_ROWS',
                    body=body
                ).execute()
            
            self.log(f"Appended {len(values)} rows to Google Sheet", "INFO")
            return True
            
        except Exception as e:
            self.log(f"Failed to append to Google Sheet: {str(e)}", "ERROR")
            return False
    
    def remove_duplicates(self, config: Dict):
        """Remove duplicate rows from Google Sheet based on all columns"""
        try:
            # Get all data from the sheet
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=config['spreadsheet_id'],
                range=config['sheet_range']
            ).execute()
            
            values = result.get('values', [])
            
            if len(values) <= 1:
                self.log("No data rows to check for duplicates", "INFO")
                return 0
            
            headers = values[0] if values else []
            unique_rows = [headers]  # Start with headers
            seen_rows = set()
            duplicates_count = 0
            
            for row in values[1:]:  # Skip header row
                # Pad row to match header length
                padded_row = row + [''] * (len(headers) - len(row))
                row_tuple = tuple(padded_row)
                
                if row_tuple not in seen_rows:
                    seen_rows.add(row_tuple)
                    unique_rows.append(padded_row)
                else:
                    duplicates_count += 1
            
            if duplicates_count > 0:
                # Clear the sheet and write unique data back
                self.sheets_service.spreadsheets().values().clear(
                    spreadsheetId=config['spreadsheet_id'],
                    range=config['sheet_range']
                ).execute()
                
                # Write unique data back
                body = {'values': unique_rows}
                self.sheets_service.spreadsheets().values().update(
                    spreadsheetId=config['spreadsheet_id'],
                    range=config['sheet_range'],
                    valueInputOption='USER_ENTERED',
                    body=body
                ).execute()
                
                self.log(f"Removed {duplicates_count} duplicate rows", "INFO")
                return duplicates_count
            else:
                self.log("No duplicate rows found", "INFO")
                return 0
                
        except Exception as e:
            self.log(f"Failed to remove duplicates: {str(e)}", "ERROR")
            return 0
    
    def run_complete_workflow(self, gmail_config: Dict, sheet_config: Dict, progress_callback=None, status_callback=None):
        """Run complete workflow: Search emails → Extract data → Append to sheet → Remove duplicates"""
        self.log("=== Starting Amazon Payment Processing Workflow ===", "INFO")
        
        overall_start = datetime.now()
        total_rows_processed = 0
        emails_processed = 0
        
        try:
            if status_callback:
                status_callback("Step 1/4: Searching for Amazon payment emails...")
            
            if progress_callback:
                progress_callback(10)
            
            # Step 1: Search for emails
            emails = self.search_emails(gmail_config)
            
            if not emails:
                self.log("No emails found matching criteria", "WARNING")
                return {'success': True, 'emails_processed': 0, 'rows_processed': 0}
            
            self.log(f"Found {len(emails)} emails to process", "INFO")
            
            if status_callback:
                status_callback(f"Step 2/4: Processing {len(emails)} emails...")
            
            if progress_callback:
                progress_callback(20)
            
            # Step 2: Process each email
            for i, email in enumerate(emails):
                try:
                    if status_callback:
                        status_callback(f"Processing email {i+1}/{len(emails)}")
                    
                    self.log(f"Processing email {i+1}/{len(emails)}", "INFO")
                    
                    # Get email body
                    email_body = self.get_email_body(email['id'])
                    
                    if not email_body:
                        self.log(f"No body found for email {email['id']}", "WARNING")
                        continue
                    
                    # Save email body to temporary file for debugging
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', encoding='utf-8', delete=False) as temp_file:
                        temp_file.write(email_body)
                        temp_path = temp_file.name
                    
                    self.log(f"Saved email body to temporary file: {temp_path}", "INFO")
                    self.log(f"Email body preview (first 500 chars): {email_body[:500]}", "DEBUG")
                    
                    # Extract payment data
                    payment_data = self.extract_payment_data(email_body)
                    
                    # Clean up temporary file
                    try:
                        os.unlink(temp_path)
                        self.log(f"Cleaned up temporary file: {temp_path}", "DEBUG")
                    except Exception as e:
                        self.log(f"Failed to clean up temporary file {temp_path}: {str(e)}", "WARNING")
                    
                    if not payment_data['table_data']:
                        self.log(f"No table data found in email {email['id']}", "WARNING")
                        continue
                    
                    # Process table data with payment columns
                    df = self.process_table_data(
                        payment_data['table_data'],
                        payment_data['payment_date'],
                        payment_data['payment_amount']
                    )
                    
                    if not df.empty:
                        # Append to sheet
                        success = self.append_to_sheet(df, sheet_config)
                        if success:
                            total_rows_processed += len(df)
                            emails_processed += 1
                            self.log(f"Successfully processed email {i+1} with {len(df)} rows", "SUCCESS")
                    
                    if progress_callback:
                        progress = 20 + ((i + 1) / len(emails)) * 50
                        progress_callback(int(progress))
                    
                except Exception as e:
                    self.log(f"Failed to process email {email.get('id', 'unknown')}: {str(e)}", "ERROR")
            
            # Step 3: Remove duplicates
            duplicates_removed = 0
            if total_rows_processed > 0:
                if status_callback:
                    status_callback("Step 3/4: Removing duplicates from Google Sheet...")
                
                self.log("Removing duplicates from Google Sheet...", "INFO")
                duplicates_removed = self.remove_duplicates(sheet_config)
            
            if progress_callback:
                progress_callback(90)
            
            # Step 4: Final summary
            if status_callback:
                status_callback("Step 4/4: Generating final report...")
            
            overall_end = datetime.now()
            duration = (overall_end - overall_start).total_seconds() / 60
            
            # Log final summary
            self.log(f"=== Workflow Completed ===", "INFO")
            self.log(f"Duration: {duration:.2f} minutes", "INFO")
            self.log(f"Emails processed: {emails_processed}", "INFO")
            self.log(f"Total rows processed: {total_rows_processed}", "INFO")
            self.log(f"Duplicates removed: {duplicates_removed}", "INFO")
            
            if progress_callback:
                progress_callback(100)
            
            if status_callback:
                status_callback(f"Workflow completed! Processed {emails_processed} emails, added {total_rows_processed} rows, removed {duplicates_removed} duplicates.")
            
            return {
                'success': True,
                'emails_processed': emails_processed,
                'rows_processed': total_rows_processed,
                'duplicates_removed': duplicates_removed,
                'duration': duration
            }
            
        except Exception as e:
            self.log(f"Workflow failed: {str(e)}", "ERROR")
            return {'success': False, 'error': str(e)}

def main():
    """Main Streamlit application"""
    st.title("💰 Amazon Payment Processor")
    st.markdown("### Extract payment details from Amazon emails and append to Google Sheets")
    
    # Initialize processor instance in session state
    if 'processor' not in st.session_state:
        st.session_state.processor = AmazonPaymentProcessor()
    
    # Initialize workflow running state
    if 'workflow_running' not in st.session_state:
        st.session_state.workflow_running = False
    
    processor = st.session_state.processor
    config = processor.get_config()
    
    # Sidebar configuration
    st.sidebar.header("Configuration")
    
    # Authentication section
    st.sidebar.subheader("🔐 Authentication")
    auth_status = st.sidebar.empty()
    
    if not processor.gmail_service or not processor.sheets_service:
        if st.sidebar.button("🚀 Authenticate with Google", type="primary"):
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            
            success = processor.authenticate_from_secrets(progress_bar, status_text)
            if success:
                auth_status.success("✅ Authenticated successfully!")
                st.sidebar.success("Ready to process workflows!")
            else:
                auth_status.error("❌ Authentication failed")
            
            progress_bar.empty()
            status_text.empty()
    else:
        auth_status.success("✅ Already authenticated")
        
        # Clear authentication button
        if st.sidebar.button("🔄 Re-authenticate"):
            if 'oauth_token' in st.session_state:
                del st.session_state.oauth_token
            st.session_state.processor = AmazonPaymentProcessor()
            st.rerun()
    
    # Main content
    if not processor.gmail_service or not processor.sheets_service:
        st.warning("⚠️ Please authenticate first using the sidebar")
        return
    
    # Configuration form
    st.header("⚙️ Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Gmail Settings")
        gmail_sender = st.text_input(
            "Sender Email",
            value=config['gmail']['sender'],
            help="Email address to search for (e.g., no-reply@amazon.com)",
            key="gmail_sender"
        )
        gmail_search_term = st.text_input(
            "Search Term",
            value=config['gmail']['search_term'],
            help="Text to search for in email subject/body",
            key="gmail_search_term"
        )
        gmail_days_back = st.number_input(
            "Days Back",
            min_value=1,
            max_value=365,
            value=config['gmail']['days_back'],
            help="Number of days to search back",
            key="gmail_days_back"
        )
        gmail_max_results = st.number_input(
            "Max Results",
            min_value=1,
            max_value=5000,
            value=config['gmail']['max_results'],
            help="Maximum number of emails to process",
            key="gmail_max_results"
        )
    
    with col2:
        st.subheader("Google Sheets Settings")
        sheet_spreadsheet_id = st.text_input(
            "Spreadsheet ID",
            value=config['sheet']['spreadsheet_id'],
            help="ID of the Google Sheets spreadsheet",
            key="sheet_spreadsheet_id"
        )
        sheet_range = st.text_input(
            "Sheet Range",
            value=config['sheet']['sheet_range'],
            help="Sheet name and range (e.g., 'amazon' or 'Sheet1!A:Z')",
            key="sheet_range"
        )
        
        st.subheader("Description")
        st.info("💡 **How it works:**\n"
               "1. Searches Gmail for Amazon payment emails\n"
               "2. Extracts payment details and invoice data\n"
               "3. Appends structured data to Google Sheets\n"
               "4. Removes duplicate entries automatically\n\n"
               "📝 **Note:** Email bodies are saved to temporary files during processing and automatically cleaned up.")
    
    # Update configuration button
    if st.button("📝 Update Configuration", type="secondary"):
        new_config = {
            'gmail': {
                'sender': gmail_sender,
                'search_term': gmail_search_term,
                'days_back': gmail_days_back,
                'max_results': gmail_max_results
            },
            'sheet': {
                'spreadsheet_id': sheet_spreadsheet_id,
                'sheet_range': sheet_range
            }
        }
        processor.update_config(new_config)
        st.success("✅ Configuration updated successfully!")
        st.rerun()
    
    st.divider()
    
    # Start workflow button
    st.header("🚀 Process Amazon Payments")
    
    if st.button("▶️ Start Payment Processing", type="primary", disabled=st.session_state.workflow_running):
        if st.session_state.workflow_running:
            st.warning("Workflow is already running. Please wait for it to complete.")
        else:
            st.session_state.workflow_running = True
            
            try:
                # Get current config
                current_config = processor.get_config()
                
                progress_container = st.container()
                with progress_container:
                    st.subheader("📊 Processing Status")
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    def update_progress(value):
                        progress_bar.progress(value)
                    
                    def update_status(message):
                        status_text.text(message)
                    
                    result = processor.run_complete_workflow(
                        current_config['gmail'],
                        current_config['sheet'],
                        progress_callback=update_progress,
                        status_callback=update_status
                    )
                    
                    if result['success']:
                        st.success(f"✅ Workflow completed successfully!")
                        st.info(f"**Summary:**\n"
                               f"- Emails processed: {result.get('emails_processed', 0)}\n"
                               f"- Rows added: {result.get('rows_processed', 0)}\n"
                               f"- Duplicates removed: {result.get('duplicates_removed', 0)}\n"
                               f"- Duration: {result.get('duration', 0):.2f} minutes")
                    else:
                        st.error(f"❌ Workflow failed: {result.get('error', 'Unknown error')}")
                
            finally:
                st.session_state.workflow_running = False
    
    # New section: Standalone duplicate removal
    st.divider()
    st.header("🧹 Clean Up Sheet")
    
    if st.button("🗑️ Remove Duplicates from Sheet", type="secondary", disabled=st.session_state.workflow_running):
        current_config = processor.get_config()
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Removing duplicates...")
        progress_bar.progress(50)
        
        duplicates_removed = processor.remove_duplicates(current_config['sheet'])
        
        progress_bar.progress(100)
        status_text.text("Complete!")
        
        if duplicates_removed > 0:
            st.success(f"✅ Removed {duplicates_removed} duplicate rows from the sheet.")
        else:
            st.info("ℹ️ No duplicate rows found.")
        
        progress_bar.empty()
        status_text.empty()
    
    st.divider()
    
    # Logs section
    st.header("📋 System Logs")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🔄 Refresh Logs", key="refresh_logs"):
            st.rerun()
    with col2:
        if st.button("🗑️ Clear Logs", key="clear_logs"):
            processor.clear_logs()
            st.success("Logs cleared!")
            st.rerun()
    with col3:
        if st.checkbox("Auto-refresh (5s)", value=False, key="auto_refresh_logs"):
            time.sleep(5)
            st.rerun()
    
    # Display logs
    logs = processor.get_logs()
    
    if logs:
        st.subheader(f"Recent Activity ({len(logs)} entries)")
        
        # Show logs in reverse chronological order (newest first)
        for log_entry in reversed(logs[-50:]):  # Show last 50 logs
            timestamp = log_entry['timestamp']
            level = log_entry['level']
            message = log_entry['message']
            
            # Color coding based on log level
            if level == "ERROR":
                st.error(f"🔴 **{timestamp}** - {message}")
            elif level == "WARNING":
                st.warning(f"🟡 **{timestamp}** - {message}")
            elif level == "SUCCESS":
                st.success(f"🟢 **{timestamp}** - {message}")
            elif level == "DEBUG":
                st.text(f"⚫ **{timestamp}** - {message}")
            else:  # INFO
                st.info(f"ℹ️ **{timestamp}** - {message}")
    else:
        st.info("No logs available. Start a workflow to see activity logs here.")
    
    # System status
    st.subheader("🔧 System Status")
    status_cols = st.columns(3)
    
    with status_cols[0]:
        st.metric("Authentication Status", 
                 "✅ Connected" if processor.gmail_service else "❌ Not Connected")
    with status_cols[1]:
        st.metric("Workflow Status", 
                 "🟡 Running" if st.session_state.workflow_running else "🟢 Idle")
    with status_cols[2]:
        st.metric("Total Logs", len(logs))


# Run the application
if __name__ == "__main__":
    main()

