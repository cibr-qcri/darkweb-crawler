import base64
import re
import ssl
from datetime import datetime
from hashlib import sha256
from ssl import SSLError
from urllib.parse import urljoin
from urllib.parse import urlparse

import requests
import socks
from bs4 import BeautifulSoup
from bs4 import Tag, NavigableString, Comment
from pysummarization.abstractabledoc.top_n_rank_abstractor import TopNRankAbstractor
from pysummarization.nlpbase.auto_abstractor import AutoAbstractor
from pysummarization.tokenizabledoc.simple_tokenizer import SimpleTokenizer
from scrapy.utils.project import get_project_settings
from scrapy_splash import SplashRequest
from socks import GeneralProxyError
from urllib3.exceptions import MaxRetryError

from .es7 import ES7

request_count = dict()


class TorHelper:

    def __init__(self):
        settings = get_project_settings()
        self.proxy_host = settings.get("TOR_PROXY_HOST")
        self.proxy_port = int(settings.get("TOR_PROXY_PORT"))
        self.es = ES7()

    @staticmethod
    def unify(url, scheme):
        if not url:
            return ""
        if url.startswith("http://") or url.startswith("https://"):
            pass
        else:
            url = "/" + url if not url.startswith("/") else url
            url = scheme + "://" + url
        return url.strip("/")

    @staticmethod
    def get_scheme(url):
        return urlparse(url).scheme

    @staticmethod
    def get_domain(url):
        net_loc = urlparse(url).netloc
        domain_levels = re.split("[.:]", net_loc)
        for idx, oni in enumerate(domain_levels):
            if idx == 0:
                continue
            if oni == "onion" and len(domain_levels[idx - 1]) in (16, 56):
                return domain_levels[idx - 1] + "." + oni

        return net_loc

    @staticmethod
    def get_onion_pattern():
        return re.compile(r"(?:https?://)?(([^/.]*)\.)*(\w{56}|\w{16})\.onion")

    def extract_links(self, urls, domain, scheme):
        external_tor = set()
        external_web = set()
        internal = set()
        for u in urls:
            if self.get_domain(u) != domain:
                if TorHelper.get_onion_pattern().match(u):
                    external_tor.add(u)
                else:
                    external_web.add(u)
            else:
                internal.add((self.unify(u, scheme)))

        return list(external_tor), list(external_web), list(internal)

    def extract_all_urls(self, url, domain, scheme, soup):
        urls = {"internal": {"anchor": [], "link": [], "script": [], "iframe": [], "meta": []},
                "external": {"anchor": {"tor": [], "web": []}, "link": {"tor": [], "web": []},
                             "script": {"tor": [], "web": []}, "iframe": {"tor": [], "web": []},
                             "meta": {"tor": [], "web": []}}}

        url_anchor = set(
            self.unify(urljoin(url, a.get("href")), scheme) for a in soup.find_all("a"))
        urls["external"]["anchor"]["tor"], urls["external"]["anchor"]["web"], urls["internal"]["anchor"] \
            = self.extract_links(url_anchor, domain, scheme)

        url_link = set(
            self.unify(urljoin(url, a.get("href")), scheme) for a in soup.find_all("link"))
        urls["external"]["link"]["tor"], urls["external"]["link"]["web"], urls["internal"]["link"] \
            = self.extract_links(url_link, domain, scheme)

        url_script = set(
            self.unify(urljoin(url, a.get("src")), scheme) for a in soup.find_all("script"))
        urls["external"]["script"]["tor"], urls["external"]["script"]["web"], urls["internal"]["script"] \
            = self.extract_links(url_script, domain, scheme)

        url_iframe = set(
            self.unify(urljoin(url, a.get("src")), scheme) for a in soup.find_all("iframe"))
        urls["external"]["iframe"]["tor"], urls["external"]["iframe"]["web"], urls["internal"]["iframe"] \
            = self.extract_links(url_iframe, domain, scheme)

        elements = soup.find_all('meta', attrs={"http-equiv": "refresh"})
        url_meta = self.get_url_meta(url, elements, scheme)
        urls["external"]["meta"]["tor"], urls["external"]["meta"]["web"], urls["internal"]["meta"] \
            = self.extract_links(url_meta, domain, scheme)

        return urls

    def get_url_meta(self, o_url, elements, scheme):
        urls = set()
        for element in elements:
            if element["content"]:
                t1 = element["content"].split(";")
                if len(t1) > 1:
                    url_content = t1[1]
                    t2 = url_content.split("=")
                    if len(t2) > 1:
                        l = t2[1].strip().replace("'", "")
                        u = urljoin(o_url, l)
                        urls.add(self.unify(u, scheme))
        return urls

    @staticmethod
    def get_all_btc(btc_addresses):
        addresses = list()
        for item in btc_addresses:
            address = item["address"]
            entry = {"address": address, "xpath": item["xpath"], "text": item["text"]}
            addresses.append(entry)

        return addresses

    @staticmethod
    def get_element_text(element, address):
        text = ""
        if element and element.parent and element.parent.parent and element.parent.parent.text:
            text = element.parent.parent.text
        elif element and element.parent and element.parent.text:
            text = element.parent.text
        elif element and element.text:
            text = element.text

        text = text.replace("\n", " ").replace("\t", " ")
        text = re.sub(" +", " ", text)
        text = text.strip()

        partitions = text.partition(address)
        left, right = partitions[0], partitions[2]
        left_text = left.split()[-50:]
        right_text = right.split()[:50]

        return " ".join([*left_text, address, *right_text])

    def get_btc(self, soup):
        btc_addresses = list()
        btc_addr_pat = re.compile(
            r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34})\b|\b(3[a-km-zA-HJ-NP-Z1-9]{25,34})\b|\b(bc1[a-zA-HJ-NP-Z0-9]{25,39})\b")

        for element in soup(text=re.compile(btc_addr_pat)):
            results = list(filter(None, [a for tup in btc_addr_pat.findall(element) for a in tup]))
            for address in results:
                if self.check_bc(address):
                    btc_addresses.append(
                        {"address": address, "xpath": self.get_node_xpath(element),
                         "text": TorHelper.get_element_text(element, address)})

        for element in soup.find_all('a', href=True):
            url = element["href"]
            domain = urlparse(url).netloc
            if '127.0.0.1' in domain or 'localhost' in domain or '0.0.0.0' in domain:
                continue
            results = list(filter(None, [a for tup in btc_addr_pat.findall(url) for a in tup]))
            for address in results:
                if self.check_bc(address):
                    btc_addresses.append(
                        {"address": address, "xpath": self.get_node_xpath(element),
                         "text": TorHelper.get_element_text(element, address)})

        return TorHelper.get_all_btc(btc_addresses)

    @staticmethod
    def decode_base58(bc, length):
        digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for char in bc:
            n = n * 58 + digits58.index(char)
        return n.to_bytes(length, 'big')

    @staticmethod
    def node_to_xpath(node):
        node_type = {
            Tag: getattr(node, "name"),
            Comment: "comment()",
            NavigableString: "text()"
        }
        same_type_siblings = list(
            node.parent.find_all(lambda x: getattr(node, "name", True) == getattr(x, "name", False),
                                 recursive=False))
        if len(same_type_siblings) <= 1:
            return node_type[type(node)] if type(node) in node_type else getattr(node, "name")
        pos = same_type_siblings.index(node) + 1

        return f"{node_type[type(node)]}[{pos}]"

    def get_node_xpath(self, node):
        xpath = "/"
        elements = [f"{self.node_to_xpath(node)}"]
        for p in node.parents:
            if p.name == "[document]":
                break
            elements.insert(0, self.node_to_xpath(p))

        xpath = "/" + xpath.join(elements)

        return xpath

    def check_bc(self, bc):
        try:
            bcbytes = self.decode_base58(bc, 25)
            return bcbytes[-4:] == sha256(sha256(
                bcbytes[:-4]).digest()).digest()[:4]
        except:
            return False

    def is_home_page(self, url):
        url = url.strip('/')
        domain = self.get_domain(url)
        scheme = self.get_scheme(url)
        base_url = scheme + "://" + domain

        return base_url == url

    def build_redirect_paths(self, history, http_redirects, first_url, last_url):
        http_redirects = dict((key.strip("/"), value) for key, value in http_redirects.items())
        redirect_urls = {}
        for res in history:
            redirect_urls[res["request"]["url"].strip("/")] = res["response"]["content"]["text"]
        current_url = first_url
        history_index = 0 if first_url != history[0]["request"]["url"].strip("/") else 1
        http = {}
        other = {}
        while current_url != last_url:
            if current_url in http_redirects:
                headers = http_redirects[current_url]
                http[current_url] = headers
                next_url = self.unify(urljoin(current_url, headers["Location"].strip("/")),
                                      self.get_scheme(current_url))
                current_url = next_url
            elif current_url in redirect_urls:
                content = base64.b64decode(redirect_urls[current_url])
                current_url = history[history_index]["request"]["url"].strip("/")
                other[current_url] = TorHelper.get_redirect_info(content, current_url)
                history_index += 1
            else:
                break

        return http, other

    @staticmethod
    def meta_refresh_exist(meta):
        is_exist = False
        if meta["content"]:
            t1 = meta["content"].split(";")
            if len(t1) > 1:
                url_content = t1[1]
                t2 = url_content.split("=")
                if len(t2) > 1:
                    is_exist = True
        return is_exist

    @staticmethod
    def get_redirect_info(content, next_url):
        soup = BeautifulSoup(content, 'lxml')
        meta_refresh = soup.find_all('meta', attrs={"http-equiv": "refresh"})
        redirect_info = {}
        if len(meta_refresh) > 0:
            min_timer = 9999.0
            redirect_to = None
            for meta in meta_refresh:
                if TorHelper.meta_refresh_exist(meta):
                    try:
                        refresh_time = meta["content"].split(";")[0].strip()
                        redirect_to = meta["content"].split(";")[1].split("=")[1].strip()
                        min_timer = min(float(refresh_time), min_timer)
                    except ValueError:
                        pass
            redirect_info["type"] = "meta"
            redirect_info["wait"] = max(min_timer - 0.5, 0)
            redirect_info["to"] = redirect_to
        else:
            redirect_info["type"] = "js"
            redirect_info["to"] = next_url

        return redirect_info

    @staticmethod
    def get_esid(url):
        es_id = sha256(url.encode("utf-8")).hexdigest()

        return es_id

    def get_tls_cert(self, domain, url):
        certificate = None
        is_valid = False
        try:
            s = socks.socksocket()
            s.setproxy(socks.PROXY_TYPE_SOCKS5, self.proxy_host, port=self.proxy_port)
            s.connect((domain, 443))
            ss = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
            certificate = ssl.DER_cert_to_PEM_cert(ss.getpeercert(True))
            ss.close()
        except (GeneralProxyError, SSLError) as e:
            return {"pem": certificate, "valid": False}

        try:
            requests.get(url.replace("http:", "https:", 1), verify=True, proxies={"https": "socks5h://{0}:{1}"
                         .format(self.proxy_host, self.proxy_port)}, allow_redirects=False)
            is_valid = True
        except (requests.exceptions.SSLError, MaxRetryError) as e:
            pass

        return {"pem": certificate, "valid": is_valid}

    def persist_http_redirects(self, http_redirect):
        for url, header in http_redirect.items():
            if self.get_onion_pattern().match(url):
                tag = {"timestamp": int(datetime.now().timestamp() * 1000), "type": "recrawl", "source": "tor",
                       "method": "html", "version": 2,
                       "info": {"response_header": {}, "domain": "", "version": "", "url": "", "homepage": False,
                                "redirect": {"url": "", "method": "http"}}
                       }
                domain = self.get_domain(url)
                scheme = self.get_scheme(url)
                headers = []
                for key, value in header.items():
                    headers.append({"key": key, "value": value})
                tag["info"]["response_header"] = headers
                tag["info"]["domain"] = domain
                tag["info"]["version"] = 3 if len(domain.replace(".onion", "")) > 16 else 2
                tag["info"]["url"] = url
                tag["info"]["scheme"] = scheme
                tag["info"]["redirect"]["url"] = header["Location"].strip("/")
                tag["info"]["redirect"]["method"] = "http"

                if scheme == "https":
                    tag["tls_cert"] = self.get_tls_cert(domain, url)

                self.es.persist_report({"data": tag}, TorHelper.get_esid(url))

    @staticmethod
    def get_lua_script():
        return """
                    treat = require("treat")

                    function main(splash, args)
                        splash:set_user_agent('Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0')
                        splash:on_request(function(request)
                            request:enable_response_body()
                        end)

                        requests = {}
                        js_files = {}
                        css_files = {}
                        splash:on_response(function(response)
                            request_accept_type = response.request.headers['Accept']
                            response_accept_type = string.lower(response.headers['Content-Type'])
                            s = response.status
                            file_extension = response.request.url:match("//[^/]+/.-(%.[^/]+)")
                            
                            if s > 300 and s <= 308 and string.find(request_accept_type, "text/html") then
                                requests[response.request.url] = response.headers
                            elseif s >= 200 and s <= 203 then
                                if string.find(response_accept_type, "script") or string.find(file_extension, ".js") then
                                    js_files[response.request.url] = treat.as_string(response.body)
                                elseif string.find(response_accept_type, "css") or string.find(file_extension, ".css") then
                                    css_files[response.request.url] = treat.as_string(response.body)
                                end
                            end
                        end)

                        splash:with_timeout(function()
                            splash:go(args.url)
                            splash:wait(args.wait)
                        end, 150)
                        splash:set_viewport_full()

                        return {
                            http_redirects = requests,
                            history = splash:history(),
                            rendered = splash:html(), 
                            jpeg = splash:jpeg(),
                            css = css_files,
                            js = js_files
                        }
                    end
                    """

    @staticmethod
    def build_splash_request(url, callback=None, wait=15):
        args = {'lua_source': TorHelper.get_lua_script(), 'timeout': 200, "wait": wait}

        request = SplashRequest(url, method='POST', callback=callback, args=args, endpoint='execute')
        return request

    @staticmethod
    def get_summary(page):
        soup = BeautifulSoup(page, "lxml")
        for s in soup.select('script'):
            s.decompose()
        for s in soup.select('style'):
            s.decompose()

        # Object of automatic summarization.
        auto_abstractor = AutoAbstractor()
        # Set tokenizer.
        auto_abstractor.tokenizable_doc = SimpleTokenizer()
        # Set delimiter for making a list of sentence.
        auto_abstractor.delimiter_list = [".", "\n"]
        # Object of abstracting and filtering document.
        abstractable_doc = TopNRankAbstractor()
        # Summarize document.
        result_dict = auto_abstractor.summarize(soup.getText(), abstractable_doc)

        summary = ""
        for sentence in result_dict["summarize_result"]:
            summary = summary + sentence.strip()

        return summary
