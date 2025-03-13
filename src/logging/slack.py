import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


class SlackClient:
    def __init__(self):
        self.client = WebClient(token=os.getenv("SLACK_TOKEN"))

    def send_message(
        self, message: str, channel: str = os.getenv("SLACK_CHANNEL_NAME")
    ):
        return
        message_blocks = self.format_malicious_packet_message(message)
        try:
            self.client.chat_postMessage(
                channel=channel,
                blocks=message_blocks,
                text="Error, message was not generated",
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
        infos = raw_message.split("\n")
        header = infos[0].strip()

        # Create Block Kit blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 {header} 🚨",
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ]

        for info in infos[1:]:
            for i in info.split(", "):
                info_block = {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*{i.split(': ')[0]}:*\t`{' '.join(i.split(': ')[1:])}`",
                        },
                    ],
                }
                blocks.append(info_block)

        blocks.extend(
            [
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "⚠️ Please investigate this issue immediately.",
                        }
                    ],
                },
            ]
        )

        return blocks
