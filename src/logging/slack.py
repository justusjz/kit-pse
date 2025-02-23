import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

class SlackClient():
    def __init__(self):
        self.client = WebClient(token=os.getenv("SLACK_TOKEN"))

    def send_message(self, message: str, channel: str = os.getenv("SLACK_CHANNEL_NAME")):
        message_blocks = self.format_malicious_packet_message(message)
        try:
            self.client.chat_postMessage(
                channel=channel,
                blocks=message_blocks
            )
        except SlackApiError as e:
            print(f"Error sending message: {e.response['error']}")

    @staticmethod
    def format_malicious_packet_message(raw_message):
        """
        Transforms a raw malicious packet message into a formatted Slack message using Block Kit.

        :param raw_message: The raw message as a string.
        :return: A dictionary containing Slack Block Kit blocks.
        """
        # Parse the raw message
        lines = raw_message.split("\n")
        header = lines[0].strip()
        mac_address = lines[1].split(": ")[1].strip()
        source_ip = lines[2].split(": ")[1].split(", ")[0].strip()
        destination_ip = lines[2].split(": ")[2].strip()
        source_port = lines[3].split(": ")[1].split(", ")[0].strip()
        destination_port = lines[3].split(": ")[2].strip()

        # Create Block Kit blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 {header} 🚨",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Possible *IP spoofing using private networks* detected."
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*MAC Address:*\n`{mac_address}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source IP:*\n`{source_ip}`"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Destination IP:*\n`{destination_ip}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source Port:*\n`{source_port}`"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Destination Port:*\n`{destination_port}`"
                    }
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "⚠️ Please investigate this issue immediately."
                    }
                ]
            }
        ]

        return blocks