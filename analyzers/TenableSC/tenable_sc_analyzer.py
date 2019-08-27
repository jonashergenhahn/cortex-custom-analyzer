#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from tenable import sc
from tenable.errors import APIError, ConnectionError


class TenableScAnalyzer(Analyzer):
    """
    Analyzer to send request to tenable.sc.

    Requests a given fqdn or ip to selected repositories and returns vulnerabilities associated to the asset.
    """

    def __init__(self):
        """
        Initialize needed parameters and establish connection to tenable.sc.
        """
        Analyzer.__init__(self)

        self.service = self.get_param("config.service", "vulns")
        self.filters = {}

        # build filter for repository ids
        try:
            self.filters["repositoryIDs"] = ("repositoryIDs", "=", ",".join(
                map(str, self.get_param("config.repositories")))
            )
        except (TypeError, KeyError):
            pass

        # just needed to establish connection to sc
        host = self.get_param("config.hostname", "localhost")
        username = self.get_param("config.username", None, "Missing tenable.sc username")
        password = self.get_param("config.password", None, "Missing tenable.sc password")
        verify = self.get_param("config.verify", True)
        proxies = {
            "https": self.get_param("config.proxy_https", None),
            "http": self.get_param("config.proxy_http", None)
        }

        try:
            self.sc = sc.TenableSC(host, ssl_verify=verify, proxies=proxies)
            self.sc.login(username, password)
        except ConnectionError as e:
            self.error(str(e))

    def __del__(self):
        """
        Logout if object get destroyed

        :return: None
        """
        try:
            self.sc.logout()
        except (APIError, AttributeError):
            # ignore errors while logout
            pass

    def __vulnerabilities(self):
        """
        Get vulns from tenable.sc for filter

        :return: a dict with all vulnerabilities for filter
        :rtype: dict
        """
        return self.sc.analysis.vulns(*self.filters.values(), json_result=True)

    def run(self):
        """
        Main function acts as controller.

        Decides on given data type and service, what functions should be called:
        - service vulns
            - allowed data type fqdn, ip

        :return: None
        """
        try:
            # check if fqdn or ip is given
            if self.service == "vulns":
                if self.data_type == "fqdn":
                    self.filters["dnsHostname"] = ("dnsName", "=", self.get_data())
                elif self.data_type == "ip":
                    self.filters["ip"] = ("ip", "=", self.get_data())
                else:
                    self.error("This data type is not supported by this analyzer.")
                self.report(self.__vulnerabilities())
            else:
                self.error("This service ist not supported by this analyzer.")
        except APIError as e:
            self.error(e)

    def summary(self, raw):
        """
        Set summary for TheHive

        :param raw: full response
        :type raw: dict
        :return: summary of vulnerabilities severity
        :rtype: dict
        """
        summary = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        if "results" in raw:
            for vulnerability in raw["results"]:
                summary[vulnerability["severity"]["name"].lower()] += 1

        taxonomies = []
        # mapping severities to level
        level = {
            "info": "info",
            "low": "info",
            "medium": "suspicious",
            "high": "malicious",
            "critical": "malicious"
        }
        namespace = "tenable.sc"

        for severity, count in summary:
            if count > 0:
                taxonomies.append(self.build_taxonomy(level[severity], namespace, severity, count))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    TenableScAnalyzer().run()
