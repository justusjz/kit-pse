import unittest
from unittest.mock import patch
from main import *

class TestContentLengthCheck(unittest.TestCase):

    @patch("main.log_malicious_packet")
    def test_content_length_mismatch(self, mock_log):

        http_packet = Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=12345, dport=80) / Raw(
            load="POST / HTTP/1.1\r\nContent-Length: 13\r\n\r\nHello, World!" 
        )

        content_length_check(http_packet)
        mock_log.assert_not_called()

        invalid_http_packet = Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=12345, dport=80) / Raw(
            load="POST / HTTP/1.1\r\nContent-Length: 13\r\n\r\nHello, World!!!"
        )

        content_length_check(invalid_http_packet)
        mock_log.assert_called_once_with(invalid_http_packet, "Content-Length mismatch detected.")

    @patch("main.log_malicious_packet")
    def test_no_content_length_header(self, mock_log):
        http_packet_no_cl = Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=12345, dport=80) / Raw(
            load="POST / HTTP/1.1\r\n\r\nHello, World!"
        )

        content_length_check(http_packet_no_cl)
        mock_log.assert_not_called()

    @patch("main.log_malicious_packet")
    def test_incomplete_header(self, mock_log):
        incomplete_http_packet = Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=12345, dport=80) / Raw(
            load="POST / HTTP/1.1\r\nContent-Length: 13\r\nHello, World!"
        )

        content_length_check(incomplete_http_packet)
        mock_log.assert_not_called()

if __name__ == "__main__":
    unittest.main()
