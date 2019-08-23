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

        self.repositories = self.get_param("config.repositories", [])
        self.service = self.get_param("config.service", "vulns")

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

    def __vulnerabilities_by_fqdn(self, data):
        """
        Checks the given fqdn in tenable.sc and returns all related vulnerabilities.

        :param data: fqdn to get all vulnerabilities
        :type data: string
        :return: a dict with all vulnerabilities associated with given fqdn
        :rtype: dict
        """
        if self.repositories is None:
            return self.sc.analysis.vulns(("dnsName", "=", data), json_result=True).json()
        else:
            return self.sc.analysis.vulns(("dnsName", "=", data), ("repositoryIDs", "=", self.repositories),
                                          json_result=True).json()

    def __vulnerabilities_by_ip(self, data):
        """
        Checks the given ip in tenable.sc and returns all related vulnerabilities

        :param data: ip address to look up
        :type data: string
        :return: a dict with all vulnerabilities associated with given ip
        :rtype: dict
        """
        if self.repositories is None:
            return self.sc.analysis.vulns(("ip", "=", data), json_result=True)
        else:
            return self.sc.analysis.vulns(("ip", "=", data), ("repositoryIDs", "=", self.repositories),
                                          json_result=True)

    def run(self):
        """
        Main function acts as controller.

        Decides on given data type and service, what functions should be called:
        - service [vulns]
        - data type [fqdn, ip]

        :return: None
        """
        try:
            # check if fqdn or ip is given
            if self.data_type == "fqdn":
                # check service
                if self.service == "vulns":
                    self.report(self.__vulnerabilities_by_fqdn(self.get_data()))
            elif self.data_type == "ip":
                # check service
                if self.service == "vulns":
                    self.report(self.__vulnerabilities_by_ip(self.get_data()))
            # not supported data type
            else:
                self.error("This data type is not supported by this analyzer.")
        except APIError as e:
            self.error(str(e))

    def summary(self, raw):
        """
        Set summary for TheHive

        :param raw: full response
        :type raw: dict
        :return: summary of vulnerabilities severity
        :rtype: dict
        """
        summary = {}
        if "results" in raw:
            count = [0, 0, 0, 0, 0]
            for vulnerability in raw["results"]:
                count[vulnerability["severity"]["id"]] += 1
            summary["info"] = count[0]
            summary["low"] = count[1]
            summary["medium"] = count[2]
            summary["high"] = count[3]
            summary["critical"] = count[4]

        taxonomies = []
        level = "info"
        namespace = "tenable.sc"
        predicate = "Info"

        if summary["info"] > 0:
            value = summary["info"]
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        if summary["low"] > 0:
            value = summary["low"]
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        if summary["medium"] > 0:
            value = summary["medium"]
            level = "suspicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        if summary["high"] > 0:
            value = summary["high"]
            level = "suspicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        if summary["critical"] > 0:
            value = summary["critical"]
            level = "malicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    TenableScAnalyzer().run()
