#
# This is sample code to understand how API works...
# Released under License https://developer.cisco.com/site/license/cisco-sample-code-license/
#
import requests
import json


class investigate (object):
    """Class to define the umbrella instance.

    Attributes
    token: API token

    """

    def __init__(self, token):
        """Return Umbrella Object whose attributes are token."""
        self.token = token
        self.url = "investigate.api.umbrella.com"
        self.headers = {
            'Authorization': 'Bearer {}'.format(token),
            'Content-Type': 'application/json'
            }

    def get(self, path):
        """GET method for umbrella."""
        try:
            response = requests.get(
                "https://{}{}".format(self.url, path),
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

    def post(self, path, data):
        """POST method for umbrella."""
        try:
            response = requests.post(
                "https://{}{}".format(self.url, path),
                data=json.dumps(data),
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

    def patch(self, path, data):
        """PATCH method for umbrella."""
        try:
            response = requests.patch(
                "https://{}{}".format(self.url, path),
                data=json.dumps(data),
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
