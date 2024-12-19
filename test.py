import unittest

suite = unittest.TestLoader().discover("src")
unittest.TextTestRunner().run(suite)
