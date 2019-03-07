#
# This is sample code to understand how API works...
# Released under License https://developer.cisco.com/site/license/cisco-sample-code-license/
#
import requests
import json


class tg_account (object):
    """Class to define the threatgrid instance.

    Attributes
    key: API key

    """

    def __init__(self, key):
        """Return Threatgrid Object whose attributes are key."""
        self.key = key
        self.url = "panacea.threatgrid.com/api/v2"
        self.headers = {
            'Content-Type': 'application/json'
            }

    def get(self, path):
        """GET method for Threatgrid."""
        try:
            response = requests.get(
                "https://{}{}&api_key={}".format(self.url, path, self.key),
                headers=self.headers
            )
            # Consider any status other than 2xx an error
            if not response.status_code // 100 == 2:
                return "Error: Unexpected response {}".format(response)
            try:
                return response.json()
            except:
                return "Error: Non JSON response {}".format(response.text)
        except requests.exceptions.RequestException as e:
                # A serious problem happened, like an SSLError or InvalidURL
                return "Error: {}".format(e)
