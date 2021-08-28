import os
from datetime import datetime
from hashlib import sha256

from .es7 import ES7
from .support import TorHelper


class TorPipeline(object):

    def __init__(self):
        self.helper = TorHelper()
        self.es = ES7()

    @staticmethod
    def write_files(item):
        date = item["date"]
        domain = item["domain"]
        url = item["url"]
        rendered_page = item["rendered_page"]
        raw_page = item["raw_page"]
        js = item["js_files"]
        css = item["css_files"]
        screenshot = item["screenshot"]

        root_dir = "/mnt/data"
        path = "{date}/{domain}".format(date=date.strftime("%d-%m-%y"), domain=domain)
        url_hash = sha256(url.encode("utf-8")).hexdigest()
        base_dir = "{path}/{file}".format(path=path, file=url_hash)
        js_dir = "{base}/js".format(base=base_dir)
        css_dir = "{base}/css".format(base=base_dir)

        rendered_page_path = None
        raw_page_path = None
        js_paths = []
        css_paths = []
        screenshot_path = None

        try:
            os.makedirs("{root}/{css}".format(root=root_dir, css=css_dir))
        except OSError:
            pass

        try:
            os.makedirs("{root}/{js}".format(root=root_dir, js=js_dir))
        except OSError:
            pass

        if rendered_page:
            rendered_page_path = "{base}/rendered.html".format(base=base_dir)
            with open("{root}/{path}".format(root=root_dir, path=rendered_page_path), encoding="utf-8", mode="w",
                      errors='ignore') as f:
                f.write(rendered_page)
        if raw_page:
            raw_page_path = "{base}/raw.html".format(base=base_dir)
            with open("{root}/{path}".format(root=root_dir, path=raw_page_path), encoding="utf-8", mode="w",
                      errors='ignore') as f:
                f.write(raw_page)
        if screenshot:
            screenshot_path = "{base}/screenshot.jpeg".format(base=base_dir)
            with open("{root}/{path}".format(root=root_dir, path=screenshot_path), mode="wb") as f:
                f.write(screenshot)
        if len(js) > 0:
            for js_url, content in js.items():
                js_url_hash = sha256(js_url.encode("utf-8")).hexdigest()
                js_path = "{js}/{index}".format(js=js_dir, index=js_url_hash)
                js_paths.append(js_path)
                with open("{root}/{js}".format(root=root_dir, js=js_path), encoding="utf-8", mode="w",
                          errors='ignore') as f:
                    f.write(content)
        if len(css) > 0:
            for css_url, content in css.items():
                css_url_hash = sha256(css_url.encode("utf-8")).hexdigest()
                css_path = "{css}/{index}".format(css=css_dir, index=css_url_hash)
                css_paths.append(css_path)
                with open("{root}/{css}".format(root=root_dir, css=css_path), encoding="utf-8", mode="w",
                          errors='ignore') as f:
                    f.write(content)

        return {
            "raw_md5": item["raw_md5"],
            "css": item["css"] or len(css) > 0,
            "js": item["js"] or len(js) > 0,
            "paths": {
                "raw": raw_page_path,
                "rendered": rendered_page_path,
                "screenshot": screenshot_path,
                "js": js_paths,
                "css": css_paths,
            }}

    def process_item(self, item, spider):
        url = item["url"]
        domain = item["domain"]
        page_info = TorPipeline.write_files(item)
        is_homepage = item["homepage"]

        tag = {
            "timestamp": int(datetime.now().timestamp() * 1000),
            "type": "service",
            "source": "tor",
            "method": "html",
            "version": 2,
            "info": {
                "version": item["version"],
                "response_header": item["response_header"],
                "homepage": is_homepage,
                "domain": domain,
                "url": url,
                "scheme": item["scheme"],
                "title": item["title"],
                "urls": item["urls"],
                "cryptocurrency": {
                    "btc": item["btc"]
                }
            },
            "page": page_info,
            "summary": TorHelper.get_summary(item["rendered_page"])
        }

        cert_info = self.helper.get_tls_cert(domain, url)
        if is_homepage and cert_info["pem"]:
            tag["info"]["tls_cert"] = self.helper.get_tls_cert(domain, url)

        if "redirect" in item:
            tag["info"]["redirect"] = item["redirect"]

        self.es.persist_report({"data": tag}, self.helper.get_esid(url))
