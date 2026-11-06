import io
import unittest
from unittest.mock import mock_open, patch

from elgamal.crypto import number_provider as numbers


class ProcessorCountersTests(unittest.TestCase):
    def test_linux_reads_only_cpu_counters(self):
        data = b'cpu  10 20 30\ncpu0 1 2 3\nintr 42\n'
        with patch.object(numbers.sys, 'platform', 'linux'), \
                patch('builtins.open', mock_open(read_data=data)) as file:
            self.assertEqual(numbers._read_processor_counters(), b'cpu  10 20 30\ncpu0 1 2 3\n')
            file.assert_called_once_with('/proc/stat', 'rb')

    def test_linux_rejects_missing_cpu_statistics(self):
        with patch.object(numbers.sys, 'platform', 'linux'), \
                patch('builtins.open', return_value=io.BytesIO(b'intr 42\n')):
            with self.assertRaises(RuntimeError):
                numbers._read_processor_counters()

    def test_windows_reads_powershell_output(self):
        with patch.object(numbers.sys, 'platform', 'win32'), \
                patch.object(numbers.subprocess, 'check_output', return_value=b'counter=42'):
            self.assertEqual(numbers._read_processor_counters(), b'counter=42')

    def test_counter_data_produces_prime_and_signature(self):
        from elgamal.crypto.elgamal import make_keys, sign, verify

        with patch.object(numbers, '_counter_state', None), \
                patch.object(numbers, '_counter_index', 0), \
                patch.object(numbers, '_read_processor_counters', return_value=b'cpu 10 20 30\n'):
            p, factors = numbers.provide_prime_and_factors(8)
            self.assertEqual(p.bit_length(), 8)
            self.assertTrue(numbers.is_prime(p))
            self.assertEqual(factors, [2, (p - 1) // 2])
            public, private, _ = make_keys(selected_p=23)
            signature, _ = sign(b'test', private)
            self.assertTrue(verify(b'test', signature, public)[0])


if __name__ == '__main__':
    unittest.main()
