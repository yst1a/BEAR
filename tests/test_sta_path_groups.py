import unittest
from bear.select import _max_path_delay_ps

class PathGroupTiming(unittest.TestCase):
    def test_data_slower_than_recovery(self):
        report='Path Group: asynchronous\n 9.7638 slack (MET)\nPath Group: clk\n 8.4959 slack (MET)\n'
        self.assertEqual(_max_path_delay_ps(report),1504.1)
    def test_group_order_and_negative_slack(self):
        a=' -0.2000 slack (VIOLATED)\n 9.0000 slack (MET)\n'
        b=' 9.0000 slack (MET)\n -0.2000 slack (VIOLATED)\n'
        self.assertEqual(_max_path_delay_ps(a),10200.0)
        self.assertEqual(_max_path_delay_ps(a),_max_path_delay_ps(b))
    def test_missing_group_is_unknown(self):
        self.assertIsNone(_max_path_delay_ps('No paths found.'))

if __name__=='__main__':unittest.main()

