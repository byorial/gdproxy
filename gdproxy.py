#########################################################
# python
import os, sys, traceback, re, json, datetime
# third-party
import requests
from flask import request, render_template, jsonify, redirect, Response
# sjva
from framework import py_urllib
from plugin import LogicModuleBase
from tool_base import ToolUtil 


#########################################################
from mod import P
name = 'gdproxy'
logger = P.logger
ModelSetting = P.ModelSetting
package_name = P.package_name

class GDproxy(LogicModuleBase):
    db_default = {
        f'{name}_db_version': '1',

        # setting
        f'{name}_remote_name': 'gdrive',
        f'{name}_chunk_size': '1048756',

        # TODO: test - video and sub
        f'{name}_test_video_fileid': '',
        f'{name}_test_subtitle_fileid': '',
    }
    def __init__(self, P):
        super(GDproxy, self).__init__(P, 'setting')
        self.name = name
        self.test = None

    def process_menu(self, sub, req):
        arg = ModelSetting.to_dict()
        arg['sub'] = self.name
        arg['proxy_url'] = ToolUtil.make_apikey_url(f'/{package_name}/api/{name}/proxy')
        try:
            return render_template(f"{package_name}_{name}_{sub}.html", arg=arg)
        except Exception as exception:
            logger.error('Exception:%s', exception)
            logger.error(traceback.format_exc())
            return render_template('sample.html', title=f"{package_name} - {sub}")

    def process_ajax(self, sub, req):
        try:
            ret = {'ret':'success'}
            return jsonify(ret)
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return jsonify({'ret':'danger', 'msg':str(e)})
 
    def process_api(self, sub, req):
        try:
            #logger.debug(f'sub: {sub}')
            logger.debug(req)

            if sub == 'proxy':
                fileid = request.args.get('f', None)
                remote_name = request.args.get('r', ModelSetting.get(f'gdproxy_remote_name'))
                kind = request.args.get('k', 'video')
                name = request.args.get('n', None) #file name for subtitle
                logger.info(f"{fileid},{remote_name},{kind},{name}")

                if not fileid:
                    logger.error('fileid is required')
                    return Response('fileid is required', 400, content_type='text/html')

                token = self.get_access_token_by_remote_name(remote_name)
                if not token:
                    return Response('Failed to get Token by remote name({remote_name})', 400, content_type='text/html')

                url = f'https://www.googleapis.com/drive/v3/files/{fileid}?alt=media'
                headers = self.get_headers(dict(request.headers), kind, token)
                r = requests.get(url, headers=headers, stream=True)
                if name != None:
                    r.headers['Content-Type'] = "text/plain"
                    r.headers['Content-Disposition'] = f'inline; filename="{name}"'

                chunk = ModelSetting.get_int('gdproxy_chunk_size')
                rv = Response(r.iter_content(chunk_size=int(chunk)), r.status_code, content_type=r.headers['Content-Type'], direct_passthrough=True)
                rv.headers.add('Content-Range', r.headers.get('Content-Range'))
                return rv
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())

    def get_headers(self, headers, kind, token):
        try:
            chunk = ModelSetting.get('gdproxy_chunk_size')
            if kind == "video":
                if 'Range' not in headers or headers['Range'].startswith('bytes=0-'):
                    headers['Range'] = f"bytes=0-{chunk}"
            else:
                if 'Range' in headers: del(headers['Range'])
            headers['Authorization'] = f"Bearer {token}"
            headers['Connection'] = 'keep-alive'
            del(headers['Host'])
            del(headers['X-Forwarded-Scheme'])
            del(headers['X-Forwarded-Proto'])
            del(headers['X-Forwarded-For'])
            if 'Cookie' in headers: del(headers['Cookie'])
            return headers
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    def get_remote_by_name(self, remote_name):
        try:
            from rclone.logic import Logic as LogicRclone
            remotes = LogicRclone.load_remotes()
            for remote in remotes:
                if remote['name'] == remote_name:
                    return remote
            return None
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    def get_access_token_by_remote_name(self, remote_name):
        try:
            remote = self.get_remote_by_name(remote_name)
            if not remote:
                logger.error(f'failed to get remote by remote_name({remote_name})')
                return None

            # for user accounts
            if 'token' in remote:
                return json.loads(remote['token'])['access_token']

            # for service accounts
            try:
                from google.auth.transport.requests import Request as GRequest
                from google.oauth2 import service_account
            except ImportError:
                os.system("{} install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib oauth2client".format(app.config['config']['pip']))

            SCOPES = ['https://www.googleapis.com/auth/drive']
            path_accounts = remote['service_account_file_path']

            import random
            path_sa_json = os.path.join(path_accounts, random.choice(os.listdir(path_accounts)))
            logger.debug(f'selected service-account-json: {path_sa_json}')

            creds = service_account.Credentials.from_service_account_file(path_sa_json, scopes=SCOPES)
            creds.refresh(GRequest())
            return creds.token
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None
