# -*- coding: utf-8 -*-

# Define here the models for your scraped items
#
# See documentation in:
# https://doc.scrapy.org/en/latest/topics/items.html

import scrapy


class TorspiderItem(scrapy.Item):
    page = scrapy.Field()
    url = scrapy.Field()
    urls = scrapy.Field()
    date = scrapy.Field()
    domain = scrapy.Field()
    title = scrapy.Field()
    homepage = scrapy.Field()
    external_links_web = scrapy.Field()
    external_links_tor = scrapy.Field()
    scheme = scrapy.Field()
    version = scrapy.Field()
    response_header = scrapy.Field()
    btc = scrapy.Field()
    rendered_page = scrapy.Field()
    raw_page = scrapy.Field()
    raw_md5 = scrapy.Field()
    js = scrapy.Field()
    css = scrapy.Field()
    screenshot = scrapy.Field()
    js_files = scrapy.Field()
    css_files = scrapy.Field()
    redirect = scrapy.Field()
