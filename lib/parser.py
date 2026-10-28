import email
from email import policy

def parse_eml(filepath):
    # emails contain raw bytes, non-ASCII text and base64 payloads
    with open(filepath, 'rb') as f:
        # policy.default automatically decodes RFC 2047 headers into plain readable strings
        msg = email.message_from_binary_file(f, policy=policy.default)

        # extract headers
        headers = {
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'reply_to': msg.get('Reply-To', ''),
            'return_path': msg.get('Return-Path', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            # use get_all() for received headers to get the list of ALL hops
            'received': msg.get_all('Received', []) or [],
            'auth_results': msg.get('Authentication-Results', ''),
            'x_mailer': msg.get('X-Mailer', ''),
            'x_originating_ip': msg.get('X-Originating-IP', ''),
        }

        # extract body
        body_plain = None
        body_html = None

        if msg.is_multipart():
            # msg.walk() recursively traverses every branch of the MIME tree
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get_content_disposition() or '')

                # ignore attachments while looking for body text
                if disposition == 'attachment':
                    continue

                # capture plain text and html versions
                if content_type == 'text/plain' and body_plain is None:
                    body_plain = part.get_content()
                elif content_type == 'text/html' and body_html is None:
                    body_html = part.get_content()
        else:
            # simple email with no attachments or alternatives
            content_type = msg.get_content_type()
            if content_type == 'text/plain':
                body_plain = msg.get_content()
            elif content_type == 'text/html':
                body_html = msg.get_content()

        # extract attachments
        attachments = []

        for part in msg.iter_attachments():
            attachments.append({
                'filename': part.get_filename() or 'unnamed_attachment',
                'content_type': part.get_content_type(),
                'data': part.get_payload(decode=True) or b''
            })

        return headers, body_plain, body_html, attachments