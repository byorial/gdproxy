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

from lib_gdrive import LibGdrive
from rclone.logic import Logic as LogicRclone

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

        f'{name}_prev_parent_id': '',

    }
    def __init__(self, P):
        super(GDproxy, self).__init__(P, 'gdrive')
        self.name = name
        self.test = None
        self.dir_cache = {}
        self.last_remote = ''
        self.last_folderid = ''
        self.last_path = ''

    def process_menu(self, sub, req):
        try:
            logger.debug(f'sub: {sub}')
            logger.debug(req)

            arg = ModelSetting.to_dict()
            arg['sub'] = self.name
            arg['proxy_url'] = ToolUtil.make_apikey_url(f'/{package_name}/api/{name}/proxy')

            if sub == 'gdrive':
                arg['remote_names'] = '|'.join(self.get_remote_names())
                arg['last_remote'] = self.last_remote
                arg['last_folderid'] = self.last_folderid
                arg['last_path'] = self.last_path
            return render_template(f"{package_name}_{name}_{sub}.html", arg=arg)
        except Exception as exception:
            logger.error('Exception:%s', exception)
            logger.error(traceback.format_exc())
            return render_template('sample.html', title=f"{package_name} - {sub}")

    def process_ajax(self, sub, req):
        try:
            logger.debug(f'AJAX sub: {sub}')
            ret = {'ret':'success'}
            if sub == 'listgdrive':
                ret = self.listgdrive(req)
            elif sub == 'reset_cache':
                self.dir_cache.clear()
                logger.debug(self.dir_cache)
                ret['msg'] = '디렉토리 캐시를 초기화하였습니다.'
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

    def get_remote_names(self):
        remotes = LogicRclone.load_remotes()
        return [x['name'] for x in remotes]

    def get_remote_by_name(self, remote_name):
        try:
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

    def listgdrive(self, req):
        try:
            ret = {}
            logger.debug(req.form)
            remote = self.get_remote_by_name(req.form['remote_name'])
            folderid = req.form['folderid']
            path = req.form['path']
            force = req.form['force']
            is_root = False


            if folderid == 'root':
                is_root = True
                if 'team_drive' in remote:
                    folderid = remote['team_drive']
                elif 'root_folder_id' in remote:
                    folderid = remote['root_folder_id']

            self.last_remote = remote['name']
            self.last_folderid = folderid
            self.last_path = path

            cache_key = remote['name'] + f':{path}'
            logger.debug(f'cache_key: {cache_key}')

            if force == 'false' and cache_key in self.dir_cache:
                ret['ret'] = 'success'
                ret['list'] = self.dir_cache[cache_key]
                logger.debug(f'{folderid} exists in cache.. return')
                return ret

            logger.debug(f'{folderid} search gdrive')
            service = LibGdrive.auth_by_rclone_remote(remote)

            if 'service_account_file' in remote:
                drive_id = remote['root_folder_id']
                children = LibGdrive.get_children_for_sa(folderid, drive_id, service=service, fields=['id','name','mimeType','trashed','size','parents','shortcutDetails'])
            else:
                children = LibGdrive.get_children(folderid, service=service, fields=['id','name','mimeType','trashed','size','parents','shortcutDetails'])

            ret['ret'] = 'success'
            schildren = sorted(children, key=(lambda x: x['name']))

            if not is_root:
                #info = LibGdrive.get_file_info(folder_id, service=service)
                #parent_id = info.data['parents'][0]
                parent_id = ModelSetting.get('gdproxy_prev_parent_id')
                pitem = [{'name':'..', 'mimeType':'application/vnd.google-apps.folder', 'id':parent_id, 'trashed':False, 'parents':[], 'size':'-'}]
                schildren = pitem + schildren

            self.dir_cache[cache_key] = schildren
            ModelSetting.set('gdproxy_prev_parent_id', folderid)
            ret['list'] = schildren
            return ret
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error', 'msg':str(e)}
