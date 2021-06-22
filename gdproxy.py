#########################################################
# python
import os, sys, traceback, re, json
from datetime import datetime, timedelta
# third-party
import requests
from flask import request, render_template, jsonify, redirect, Response
# sjva
from framework import py_urllib, SystemModelSetting
from plugin import LogicModuleBase
from tool_base import ToolUtil 

from lib_gdrive import LibGdrive
from tool_base import ToolRclone

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
        f'{name}_gds_remote_name': 'mount0196',

        # for cache
        f'{name}_prev_parent_id': '',
        f'{name}_dir_cache_limit':'1000',
        f'{name}_dir_cache':'{}',
        f'{name}_last_remote':'',
        f'{name}_last_folderid':'',
        f'{name}_last_path':'',

        # for GDS
        f'{name}_auto_start': 'False',
        f'{name}_interval': '10',
        f'{name}_watch_remote': 'mount0196',
        f'{name}_plex_path_rule': 'mount0196:/|/mnt/gds',
        f'{name}_rc_addr': '127.0.0.1:5582',
        f'{name}_rc_user': 'sjva',
        f'{name}_rc_pass': 'sjva',
    }
    def __init__(self, P):
        super(GDproxy, self).__init__(P, 'gdrive')
        self.name = name
        self.test = None
        self.dir_cache = {}
        self.last_remote = ''
        self.last_folderid = ''
        self.last_path = ''
        self.dir_cache = {}
        self.token_cache = {}

    def plugin_load(self):
        self.dir_cache = json.loads(ModelSetting.get('gdproxy_dir_cache'))
        logger.debug('load dircache: '+str(len(self.dir_cache))+ ' item(s) loaded')
        self.last_remote = ModelSetting.get('gdproxy_last_remote')
        self.last_folderid = ModelSetting.get('gdproxy_last_folderid')
        self.last_path = ModelSetting.get('gdproxy_last_path')

        #self.last_token = ModelSetting.get('gdproxy_last_token')

    def plugin_unload(self):
        logger.debug('dump dircache: '+str(len(self.dir_cache))+' item(s) dumped')
        ModelSetting.set('gdproxy_dir_cache', json.dumps(self.dir_cache));
        ModelSetting.set('gdproxy_last_remote', self.last_remote)
        ModelSetting.set('gdproxy_last_folderid', self.last_folderid)
        ModelSetting.set('gdproxy_last_path', self.last_path)
        #ModelSetting.set('gdproxy_last_token', self.last_token)

    def process_menu(self, sub, req):
        try:
            logger.debug(f'sub: {sub}')
            logger.debug(req)

            arg = ModelSetting.to_dict()
            arg['sub'] = self.name
            arg['proxy_url'] = ToolUtil.make_apikey_url(f'/{package_name}/api/{name}/proxy')

            # TODO
            #arg['scheduler'] = str(scheduler.is_include(self.get_scheduler_name()))
            #arg['is_running'] = str(scheduler.is_running(self.get_scheduler_name()))

            if sub == 'gdrive':
                arg['remote_names'] = '|'.join(self.get_remote_names())
                arg['last_remote'] = self.last_remote
                arg['last_folderid'] = self.last_folderid
                arg['last_path'] = self.last_path
            elif sub == 'video' or sub == 'vrvideo':
                arg['play_title'] = req.form['play_title']
                arg['play_source_src'] = req.form['play_source_src']
                arg['play_source_type'] = req.form['play_source_type']

                if 'play_subtitle_src' in req.form:
                    arg['play_subtitle_src'] = req.form['play_subtitle_src']
                if sub == 'vrvideo':
                    arg['play_vr_projection'] = req.form['play_vr_projection']
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
 
    def scheduler_function(self):
        self.task()

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

                logger.debug(f'remote_name: {remote_name}')
                token = self.get_access_token_by_remote_name(remote_name, fileid)
                if not token:
                    return Response('Failed to get Token by remote name({remote_name})', 400, content_type='text/html')

                url = f'https://www.googleapis.com/drive/v3/files/{fileid}?alt=media'
                headers = self.get_headers(dict(request.headers), kind, token)
                #logger.debug(headers)
                r = requests.get(url, headers=headers, stream=True)
                if kind == 'subtitle':
                    logger.debug(r.encoding)
                    if r.encoding != None:
                        if r.encoding == 'ISO-8859-1': # 한글자막 인코딩 예외처리
                            try:
                                text = r.content.decode('utf-8', "strict")
                            except Exception as e:
                                logger.error('Exception:%s', e)
                                logger.error(traceback.format_exc())
                                text = r.content.decode('utf-8', "ignore")
                        else:
                            text = r.content.decode(r.encoding, "ignore")
                    else:
                        text = r.text
                    vtt = self.srt2vtt(text)
                    r.headers['Content-Type'] = "text/vtt; charset=utf-8"
                    r.headers['Content-Disposition'] = f'inline; filename="subtitle.vtt"'
                    r.headers['Content-Transfer-Encoding'] = 'binary'
                    rv = Response(vtt, r.status_code, content_type=r.headers['Content-Type'])
                    rv.headers.add('Content-Type', r.headers.get('Content-Type'))
                    rv.headers.add('Content-Disposition', r.headers.get('Content-Disposition'))
                    rv.headers.add('Content-Transfer-Encoding', r.headers.get('Content-Transfer-Encoding'))
                    return rv

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
            else: # subtitle
                headers['Accept-Charset'] = 'utf-8, iso-8859-1;q=0.5'
                if 'Range' in headers: del(headers['Range'])
            headers['Authorization'] = f"Bearer {token}"
            headers['Connection'] = 'keep-alive'
            if 'Host' in headers: del(headers['Host'])
            if 'X-Forwarded-Scheme' in headers: del(headers['X-Forwarded-Scheme'])
            if 'X-Forwarded-Proto' in headers: del(headers['X-Forwarded-Proto'])
            if 'X-Forwarded-For' in headers:  del(headers['X-Forwarded-For'])
            if 'Cookie' in headers: del(headers['Cookie'])
            return headers
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    def get_remote_names(self):
        remotes = ToolRclone.config_list()
        return [x for x in remotes.keys()]

    def get_remote_by_name(self, remote_name):
        try:
            remotes = ToolRclone.config_list()
            if remote_name in remotes:
                return remotes[remote_name]
            return None
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    def get_access_token_by_remote_name(self, remote_name, fileid):
        try:
            remote = self.get_remote_by_name(remote_name)
            if not remote:
                logger.error(f'failed to get remote by remote_name({remote_name})')
                return None

            key = f'{remote_name}:{fileid}'
            now = datetime.now()

            # token_cache에 있는 경우
            if key in self.token_cache and now < self.token_cache[key]['time'] + timedelta(minutes=5):
                logger.debug(f'{key} in token_cache: return')
                return self.token_cache[key]['token']

            # 구드 바로보기 리모트인 경우 처리
            if remote_name == ModelSetting.get('gdproxy_gds_remote_name'):
                userid = SystemModelSetting.get('sjva_me_user_id')
                apikey = SystemModelSetting.get('auth_apikey')
                gds_url = f"https://sjva.me/sjva/gds.php?type=file&id={fileid}&user_id={userid}&user_apikey={apikey}"
                data = requests.get(gds_url).json()['data']
                token = data['token']
                self.token_cache[key] = {'token':token, 'time':now}
                logger.debug(f'{key}: gds_remote auth')
                return token

            # for user accounts
            if 'token' in remote:
                expiry = datetime.strptime(remote['token']['expiry'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
                if now > expiry:
                    logger.debug('access token expired..')
                    ToolRclone.lsjson(f"{remote_name}:/")
                    return self.get_access_token_by_remote_name(remote_name, fileid)

                logger.debug(f'{key}: user auth')
                return remote['token']['access_token']

            # for service accounts
            try:
                from google.auth.transport.requests import Request as GRequest
                from google.oauth2 import service_account
            except ImportError:
                os.system("{} install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib oauth2client".format(app.config['config']['pip']))

            scopes = ['https://www.googleapis.com/auth/{}'.format(remote['scope'])]
            path_accounts = remote['service_account_file_path']

            import random
            path_sa_json = os.path.join(path_accounts, random.choice(os.listdir(path_accounts)))
            logger.debug(f'selected service-account-json: {path_sa_json}')

            creds = service_account.Credentials.from_service_account_file(path_sa_json, scopes=scopes)
            creds.refresh(GRequest())

            logger.debug(f'{key}: sa auth')
            self.token_cache[key] = {'token': creds.token, 'time':now}
            return creds.token
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    def listgdrive(self, req):
        try:
            ret = {}
            logger.debug(req.form)
            remote_name = req.form['remote_name']
            remote = self.get_remote_by_name(remote_name)
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

            self.last_remote = remote_name
            self.last_folderid = folderid
            self.last_path = path

            cache_key = remote_name + f':{path}'
            logger.debug(f'cache_key: {cache_key}')

            if force == 'false' and cache_key in self.dir_cache:
                ret['ret'] = 'success'
                if 'count' not in self.dir_cache[cache_key]:
                    self.dir_cache[cache_key] = {'cache': self.dir_cache[cache_key], 'count':0}

                self.dir_cache[cache_key]['count'] = self.dir_cache[cache_key]['count'] + 1
                ret['list'] = self.dir_cache[cache_key]['cache']
                logger.debug(f'{folderid} exists in cache.. return')
                return ret

            logger.debug(f'{folderid} search gdrive')
            service = None
            service = LibGdrive.auth_by_rclone_remote(remote)
            if not service:
                logger.error('failed to auth gdrive api')
                return {'ret':'error', 'msg':'failed to auth gdrive api'}

            if 'service_account_file' in remote:
                drive_id = remote['root_folder_id']
                children = LibGdrive.get_children_for_sa(folderid, drive_id, service=service, fields=['id','name','mimeType','trashed','size','parents','shortcutDetails'])
            else:
                children = LibGdrive.get_children(folderid, service=service, fields=['id','name','mimeType','trashed','size','parents','shortcutDetails'])

            if children == None:
                logger.error(f'failed to get children: {folderid}')
                return {'ret':'error', 'msg':f'failed to children: {folderid}'}

            ret['ret'] = 'success'
            schildren = sorted(children, key=(lambda x: x['name']))

            if not is_root:
                parent_id = ModelSetting.get('gdproxy_prev_parent_id')
                pitem = [{'name':'..', 'mimeType':'application/vnd.google-apps.folder', 'id':parent_id, 'trashed':False, 'parents':[], 'size':'-'}]
                schildren = pitem + schildren

            # cache limit over: delete item
            if len(self.dir_cache) == ModelSetting.get_int('gdproxy_dir_cache_limit'):
                del_key = sorted(self.dir_cache, key=lambda x: (self.dir_cache[x]['count']))[0]
                logger.info(f'dir_cache limits over: delete({del_key}) from cache')
                del(self.dir_cache[del_key])

            count = 1
            if cache_key in self.dir_cache:
                if 'count' in self.dir_cache[cache_key]:
                    count = self.dir_cache[cache_key]['count'] + 1

            self.dir_cache[cache_key] = {'cache':schildren, 'count':count}
            ModelSetting.set('gdproxy_prev_parent_id', folderid)
            ret['list'] = schildren
            return ret
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error', 'msg':str(e)}

    def srt2vtt(self, srt):
        try:
            logger.debug('convert srt to vtt')
            vtt = 'WEBVTT\n\n'
            lines = srt.splitlines()
            for line in lines:
                convline = re.sub(',(?! )', '.', line)
                vtt = vtt + convline + '\n'
            #logger.debug(vtt)
            return vtt
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    def task(self):
        try:
            remote
            pass
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None


