#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from os import error
import requests
import argparse
import json
import time
import math
import os
import random
from urllib.parse import urlparse as parse_url
from urllib.parse import urlencode
import hmac
import base64
from hashlib import sha256


class Constants:
    RECORD_TYPES = ['A', 'CNAME', 'MX', 'TXT', 'NS', 'AAAA', 'SRV']


class __(object):
    def __init__(self, fmt: str, *args, **kwargs):
        self.fmt = fmt
        self.args = args
        self.kwargs = kwargs

    def __str__(self):
        return self.fmt.format(*self.args, **self.kwargs)


class ApiConfig(object):
    '''Api config for dnspod'''

    def __init__(self, secret_id: str, secret_key: str, api_url: str) -> None:
        super().__init__()
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.api_url = api_url


class CommandArgs(object):
    '''命令参数'''
    config: ApiConfig = None

    def __init__(self, args) -> None:
        super().__init__()
        self.action = ''
        self.http_method = 'GET'
        if args is None:
            raise Exception('错误的参数，必须传递args')

    def to_request_params(self):
        ts = math.floor(time.time())
        r = random.randint(100, 1000000)
        data = {"Action": self.action, "Timestamp": str(
            ts), 'SecretId': self.config.secret_id, 'SignatureMethod': 'HmacSHA256',
            'Nonce': str(r)}
        return data

    def join_params_as_query(self, params: dict):
        keys = list(params.keys())
        keys.sort()
        param_str = ''
        for k in keys:
            if len(param_str) > 0:
                param_str += '&'
            param_str += __('{}={}', k, params[k]).__str__()
        return param_str

    def generate_signature(self, params: dict):
        '''构造签名'''
        param_str = self.join_params_as_query(params)
        url_parse_result = parse_url(self.config.api_url)
        host = url_parse_result.netloc
        path = url_parse_result.path
        signature_raw_str = __(
            '{}{}{}?{}', self.http_method, host, path, param_str).__str__()
        encoding = 'utf-8'
        signature = base64.b64encode(
            hmac.new(self.config.secret_key.encode(encoding), signature_raw_str.encode(encoding),
                     digestmod=sha256).digest())
        params['Signature'] = signature.decode(encoding)
        full_url = __('{}?{}', self.config.api_url,
                      urlencode(params)).__str__()
        return params, full_url


class DomainQueryCommandArgs(CommandArgs):
    '''域名查询参数'''

    def __init__(self, args) -> None:
        super().__init__(args)
        self.domain = args.domain


class ListCommand(CommandArgs):
    '''列表名称'''

    def __init__(self, args) -> None:
        super().__init__(args)
        self.offset = args.offset
        self.total = args.count

    def to_request_params(self):
        data = super().to_request_params()
        data['offset'] = self.offset
        data['length'] = self.total
        return data


class DomainListCommandArgs(ListCommand):
    '''域名列表命令行参数'''

    def __init__(self, args) -> None:
        super().__init__(args)
        self.action = 'DomainList'

    def to_request_params(self):
        data = super().to_request_params()
        return data


class DomainRecordListCommandArgs(ListCommand):
    '''域名记录列表'''

    def __init__(self, args) -> None:
        super().__init__(args)
        self.action = 'RecordList'
        self.domain = args.domain
        self.record_type = args.record_type

    def to_request_params(self):
        data = super().to_request_params()
        if self.record_type is not None and len(self.record_type) > 0 and Constants.RECORD_TYPES.count(self.record_type) >= 0:
            data['recordType'] = self.record_type
        data['domain'] = self.domain
        return data


class DomainRecordAddCommandArgs(CommandArgs):
    '''域名记录列表'''

    def __init__(self, args) -> None:
        super().__init__(args)
        self.action = 'RecordCreate'
        self.domain = args.domain
        self.record_type = args.record_type
        self.line = args.line
        self.value = args.value
        self.ttl = args.ttl
        self.sub_domain = args.sub_domain
        self.mx_priority = args.mx_priority

    def to_request_params(self):
        data = super().to_request_params()
        if self.record_type is not None and len(self.record_type) > 0 and Constants.RECORD_TYPES.count(self.record_type) >= 0:
            data['recordType'] = self.record_type
        data['domain'] = self.domain
        data['recordLine'] = self.line
        data['value'] = self.value
        data['ttl'] = self.ttl
        data['subDomain'] = self.sub_domain
        if self.record_type.lower() == 'mx':
            data['mx'] = self.mx_priority
        return data


class DomainRecordUpdateCommandArgs(DomainRecordAddCommandArgs):
    '''DNS记录更新命令'''

    def __init__(self, args) -> None:
        super().__init__(args)
        self.domain = args.domain
        self.action = 'RecordModify'
        self.id = args.id

    def to_request_params(self):
        data = super().to_request_params()
        data['recordId'] = self.id
        return data


class DomainRecordDeleteCommandArgs(CommandArgs):
    '''DNS记录删除命令'''

    def __init__(self, args) -> None:
        super().__init__(args)
        self.id = args.id
        self.action = 'RecordDelete'
        self.domain = args.domain

    def to_request_params(self):
        data = super().to_request_params()
        data['recordId'] = self.id
        data['domain'] = self.domain
        return data


class CommandHandler(object):
    '''命令执行器'''

    def __init__(self, args: CommandArgs) -> None:
        super().__init__()
        self.cmd_args = args

    def build_url(self, params: dict):
        return self.cmd_args.generate_signature(params)

    def execute(self):
        if self.cmd_args.config is None:
            raise Exception('Bad config')
        _, url = self.build_url(self.cmd_args.to_request_params())
        response = requests.request(method=self.cmd_args.http_method, url=url)
        if response.status_code == 200 and response.json()['code'] == 0:
            return True, response.json()['data'] if response.json().keys().__contains__('data') else response.json()['message']
        else:
            return False, __('{}: {}', response.json()['message'], str(response.json()['code'])).__str__()


class DomainListCommandHandler(CommandHandler):
    '''domain列表执行器'''

    def __init__(self, args: DomainListCommandArgs) -> None:
        super().__init__(args)

    def execute(self):
        ok,  data = super().execute()
        if not ok:
            print("Failed to query data", data)
            return ok, data
        for item in data['domains']:
            print(item['id'], item['name'], item['punycode'])
        return ok, data


class DomainRecordListCommandHandler(CommandHandler):
    '''DNS记录列表'''

    def __init__(self, args: DomainListCommandArgs) -> None:
        super().__init__(args)

    def execute(self):
        ok, data = super().execute()
        if not ok:
            print("Failed to query data", data)
            return ok, data
        for item in data['records']:
            print(item['id'], item['type'], item['name'],
                  item['value'], item['ttl'], item['status'])
        return ok, data


class DomainRecordAddCommandHandler(CommandHandler):
    '''记录添加命令处理器'''

    def __init__(self, args: DomainRecordAddCommandArgs) -> None:
        super().__init__(args)

    def execute(self):
        ok, data = super().execute()
        if not ok:
            print("Failed to add record", data)
            return ok, data
        record = data['record']
        print(record['id'], record['name'], record['status'])


class DomainRecordUpdateCommandHandler(CommandHandler):
    '''记录更新命令处理器'''

    def execute(self):
        ok, data = super().execute()
        if not ok:
            print("Failed to update record", data)
            return ok, data
        record = data['record']
        print(record['id'], record['name'], record['status'])


class DomainRecordDeleteCommandHandler(CommandHandler):
    '''记录删除命令处理器'''

    def __init__(self, args: DomainRecordDeleteCommandArgs) -> None:
        super().__init__(args)

    def execute(self):
        ok, data = super().execute()
        if not ok:
            print("Failed to delete record", data)
            return ok, data
        print(data)


class ArgumentsBuilder(object):
    '''参数构造器'''

    def __init__(self, parser: argparse.ArgumentParser) -> None:
        super().__init__()
        self.parser = parser

    def add_paging_params(self, args: argparse.ArgumentParser):
        args.add_argument(
            '--offset', type=int, default='0', required=False, dest='offset')
        args.add_argument(
            '--count', type=int, default='100', required=False, dest='count')

    def buildDomainSubCommandQuery(self, query_group: argparse.ArgumentParser):
        '''域名列表'''
        query_subcommands = query_group.add_subparsers(help='Query domains')
        list_args = query_subcommands.add_parser('list')
        self.add_paging_params(list_args)
        list_args.set_defaults(handler=DomainListCommandHandler)
        list_args.set_defaults(model=DomainListCommandArgs)

    def buildDomainSubCommands(self, sub_command_parser: argparse.ArgumentParser) -> None:
        domain_commands = sub_command_parser.add_subparsers()
        query_group = domain_commands.add_parser('query')
        self.buildDomainSubCommandQuery(query_group)

    def buildRecordSubCommandQuery(self, query_group: argparse.ArgumentParser) -> None:
        query_subcommands = query_group.add_subparsers(help='Query records')
        list_arg_parser = query_subcommands.add_parser('list')
        self.add_paging_params(list_arg_parser)
        list_arg_parser.add_argument(
            '--type', type=str, choices=Constants.RECORD_TYPES, dest='record_type',
            default='',
            required=False)
        list_arg_parser.add_argument(
            '--domain', type=str, dest='domain',
            required=True)
        list_arg_parser.set_defaults(handler=DomainRecordListCommandHandler)
        list_arg_parser.set_defaults(model=DomainRecordListCommandArgs)

    def buildRecordSubCommandAdd(self, add_group: argparse.ArgumentParser) -> None:
        add_group.add_argument('--domain', type=str, dest='domain',
                               required=True)
        add_group.add_argument('--subdomain', type=str, dest='sub_domain',
                               required=True)
        add_group.add_argument(
            '--line', type=str, dest='line', required=False, default='默认')
        add_group.add_argument('--type', type=str, dest='record_type',
                               required=True, choices=Constants.RECORD_TYPES)
        add_group.add_argument('--value', type=str,
                               dest='value', required=True)
        add_group.add_argument('--ttl', type=str,
                               dest='ttl', required=False, default='600')
        add_group.add_argument('--mx', type=str,
                               dest='mx_priority', required=False, default='10')
        add_group.set_defaults(handler=DomainRecordAddCommandHandler)
        add_group.set_defaults(model=DomainRecordAddCommandArgs)

    def buildRecordSubCommandUpdate(self, update_group: argparse.ArgumentParser) -> None:
        self.buildRecordSubCommandAdd(update_group)
        update_group.add_argument('--id', type=str, dest='id', required=True)
        update_group.set_defaults(handler=DomainRecordAddCommandHandler)
        update_group.set_defaults(model=DomainRecordUpdateCommandArgs)

    def buildRecordSubCommandDelete(self, delete_group: argparse.ArgumentParser) -> None:
        delete_group.add_argument('--id', type=str, dest='id', required=True)
        delete_group.add_argument(
            '--domain', type=str, dest='domain', required=True)
        delete_group.set_defaults(handler=DomainRecordDeleteCommandHandler)
        delete_group.set_defaults(model=DomainRecordDeleteCommandArgs)

    def buildRecordSubCommands(self, sub_command_parser: argparse.ArgumentParser) -> None:
        record_commands = sub_command_parser.add_subparsers()
        # query group
        query_group = record_commands.add_parser('query')
        self.buildRecordSubCommandQuery(query_group)
        # add group
        add_group = record_commands.add_parser('add')
        self.buildRecordSubCommandAdd(add_group)
        # remove group
        delete_group = record_commands.add_parser('delete')
        self.buildRecordSubCommandDelete(delete_group)
        # update group
        update_group = record_commands.add_parser('update')
        self.buildRecordSubCommandUpdate(update_group)

    def build(self) -> None:
        sub_commands_parsers = self.parser.add_subparsers()
        self.parser.add_argument('-C', required=True, type=str,
                                 help='Config file(json) path', dest='config_path')
        # domain related command
        domain_command = sub_commands_parsers.add_parser('domain')
        self.buildDomainSubCommands(domain_command)
        # record related command
        record_command = sub_commands_parsers.add_parser('record')
        self.buildRecordSubCommands(record_command)


def build_argparser():
    '''构造参数解析器'''
    parser = argparse.ArgumentParser()
    ArgumentsBuilder(parser).build()
    return parser


def main():
    parser: argparse.ArgumentParser = build_argparser()
    options: argparse.Namespace = parser.parse_args()
    try:
        handler = options.handler
        model = options.model
        config_path = options.config_path
        if not os.path.exists(config_path) or not os.path.isfile(config_path):
            raise Exception(
                __('Config file {} was neither not found or not a file', config_path))
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
            CommandArgs.config = ApiConfig(
                config_data['secretId'], config_data['secretKey'], config_data['apiUrl'])
            handler(model(options)).execute()
    except error as e:
        print(e)
        parser.print_help()


if __name__ == '__main__':
    main()
