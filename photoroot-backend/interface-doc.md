# 接口文档

## 登录

```shell
curl --location 'http://127.0.0.1:11990/login' \
--header 'Content-Type: application/json' \
--data '{
    "username": "root",
    "password": "root"
}'
```

成功响应

```json
{
    "data": {
        "token": "cc3fe936-ea11-4cc2-9d16-fc93358c531a"
    },
    "success": true
}
```

失败响应

```json
{
    "data": "Permission authentication failed",
    "success": false
}
```

## 登出

```shell
curl --location 'http://127.0.0.1:11990/logout' \
--header 'token: cc3fe936-ea11-4cc2-9d16-fc93358c531a'
```

成功响应

```json
{
    "data": "ok",
    "success": true
}
```

失败响应

```json
{
    "data": "Permission authentication failed",
    "success": false
}
```

## 获取用户图片分组

```shell
curl --location 'http://127.0.0.1:11990/groups' \
--header 'token: 2f38acba-f464-4c25-8c02-08ddf4df3252'
```

成功响应

```json
{
    "data": [
        "工作",
        "日常"
    ],
    "success": true
}
```

失败响应

```json
{
    "data": "Permission authentication failed",
    "success": false
}
```

## 上传示例(支持多文件上传)

```html
<body>
    <div class="hello">hello photoroot</div>
    <span>
        <label>token:</label> <input id="token" placeholder="token">
    </span>
    <h2>上传文件</h2>
    <div>
        <input id="group" type="text" placeholder="图片分组">
        <input type="file" id="files" multiple>
        <button id="update">上传</button>
    </div>
    <script>
        // 文件上传
        function uploadFiles(token, group, fileInput) {
            var files = fileInput.files;
            var formData = new FormData();

            for (var i = 0; i < files.length; i++) {
                var file = files[i];
                formData.append('files', file, file.name);
                console.log(`add file ${file.name}`);
            }
            var xhr = new XMLHttpRequest();
            // 上传进度监听器
            xhr.upload.addEventListener('progress', function(event) {
                if (event.lengthComputable) {
                    var percentComplete = (event.loaded / event.total) * 100;
                    console.log('总体上传进度：' + percentComplete + '%');
                } else {
                    console.log('上传进度未知');
                }
            });

            // 上传完成处理
            xhr.onload = function() {
                if (xhr.status === 200) {
                    console.log('上传完成');
                } else {
                    console.log('上传失败');
                }
            };

            // 设置请求
            xhr.open('POST', `/upload/${group}`, true);
            xhr.setRequestHeader('token', token);
            xhr.send(formData);
        }
        document.getElementById("update").addEventListener("click", function() {
            uploadFiles(document.getElementById("token").value, 
            document.getElementById("group").value,
            document.getElementById('files'));
        });
    </script>
</body>
```

