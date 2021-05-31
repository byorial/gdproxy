# gdproxy 
## gdrive proxy module for SJVA
- gdrive에 있는 파일을 rclone.conf 파일을 이용하여 인증하여 웹에서 바로 플레이 가능하도록 하는 모듈
---
## 사용법
- 모듈 설치 후 동영상 주소를 아래와 같이 설정 
- [SJVA주소]/mod/api/gdproxy/proxy?apikey=[SJVA API KEY]&fileid=[gdrive 파일ID]
  ```html
  <video controls autostart="true" playsinline id="myVideo">
  <source type="video/mp4" src="https://mysjva.juso/mod/api/gdproxy/proxy?apikey=123456789&fileid=1x2a3b4c5f6g...-" width="720px"/>
  </video>```

* 조건: 툴 - Rclone 사용, rclone.conf 기준 리모트명을 모듈 설정에 지정
