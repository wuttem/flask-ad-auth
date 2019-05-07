import unittest
import time

from flask import Flask
from flask_ad_auth import ADAuth, User


class TestDatabase(unittest.TestCase):
    @classmethod
    def _create_app(cls):
        app = Flask("test_ad_auth")
        return app

    def setUp(self):
        super(TestDatabase, self).tearDown()
        self.app = self._create_app()
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        super(TestDatabase, self).tearDown()
        self.app_context.pop()

    def test_base(self):
        ad = ADAuth()
        ad.init_app(self.app)
        self.assertTrue(ad)

        exp = time.time() + 100
        u1 = User("test@test.at", "acc_token", "refresh_token", exp, "token_type", "res", "scope",
                  group_string="group1;group2", metadata={"foo": "bar"})
        ad.store_user(u1)
        u2 = ad.get_user("test@test.at")
        self.assertEqual(u1.to_dict(), u2.to_dict())
        u3 = User.from_dict(u1.to_dict())
        self.assertEqual(u1.to_dict(), u3.to_dict())


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
