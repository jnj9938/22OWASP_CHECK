module.exports = {
    HTML:function(list){
        return `
        <!DOCTYPE html>
        <html>
        <head>
         <meta charset="UTF-8">
            <!-- Custom styles for this template -->
            <link rel="stylesheet" type="text/css" href="/css/index.css" >
            <link rel="stylesheet" type="text/css" href="/css/h.css">
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">
            <style>
             h3, h1 {
               text-align: center;
             }
            </style>
        <!-- 부가적인 테마 -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap-theme.min.css">
        
        <!-- 합쳐지고 최소화된 최신 자바스크립트 -->
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js"></script>
        
            <style type="text/css"> a { text-decoration:none }</style>
        </head>
        <body>
        <div class="menu-container">
  <ul class="vertical-nav">
    <li>
           <a class="naver-icon" href="https://www.joongbu.ac.kr/" target="_blank"><img src="/image/중부대학교.png" width="60"></a>

    </li>
    <li>
      <a href="#"><svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-person-plus" viewBox="0 0 16 16">
  <path d="M6 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H1s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C9.516 10.68 8.289 10 6 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z"/>
  <path fill-rule="evenodd" d="M13.5 5a.5.5 0 0 1 .5.5V7h1.5a.5.5 0 0 1 0 1H14v1.5a.5.5 0 0 1-1 0V8h-1.5a.5.5 0 0 1 0-1H13V5.5a.5.5 0 0 1 .5-.5z"/>
</svg>내 정보</a>
      <div class="hover-menu">
        <ul>
          <li><a href="/logout">로그아웃</a></li>
          <li><a href="/member_data">진단결과</a></li>
          
        </ul>
      </div>
    </li>
    <li>
      <a href="/profile"><svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-people-fill" viewBox="0 0 16 16">
  <path d="M7 14s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1H7zm4-6a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/>
  <path fill-rule="evenodd" d="M5.216 14A2.238 2.238 0 0 1 5 13c0-1.355.68-2.75 1.936-3.72A6.325 6.325 0 0 0 5 9c-4 0-5 3-5 4s1 1 1 1h4.216z"/>
  <path d="M4.5 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z"/>
</svg>제작자<br>프로필</a>
      

    <li class="log-out">
      <a title="홈페이지" href="/"><svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-house-door" viewBox="0 0 16 16">
  <path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4.5a.5.5 0 0 0 .5-.5v-4h2v4a.5.5 0 0 0 .5.5H14a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146zM2.5 14V7.707l5.5-5.5 5.5 5.5V14H10v-4a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v4H2.5z"/>
</svg></a>
    </li>
  </ul>
</div>
             <h1><br>진단 목록</h1><br>
          ${list}

        </body>
        </html> 
        `;
    },
    
    list:function(_url){
      var list = '<ol>';
      var i = 0;
      while(i < _url.length){
        list = list + `<li><h3>${i+1}.<a href='/member_record/${_url[i].id}'>${_url[i].URL}</a></h3></li>`;
        i = i + 1;
      }
      list = list + '</ol>';
      return list;  
    },
    
    
    result:function(sqlin, sql_info, CSRF, CSRF_info, cookie, cookie_info, http, http_info, bruteForce, bruteForce_info, XSS, XSS_info, base64Vul, sessionVul, sniff){
      return `
     <!DOCTYPE html>
      <html>
      <head>
      <meta charset="UTF-8">
         <!-- Custom styles for this template -->
         <link rel="stylesheet" type="text/css" href="/css/index.css" >
         <link rel="stylesheet" type="text/css" href="/css/h.css">
         <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">
         <!-- Required meta tags -->
         <meta charset="utf-8">
         <meta name="viewport" content="width=device-width, initial-scale=1">
         <style>
          table {
             margin-left: 10%;
             display:inline;
             text-align:left;
           }
           
         </style>
         <!-- Bootstrap CSS -->
         <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-uWxY/CJNBR+1zjPWmfnSnVxwRheevXITnMqoEIeG1LJrdI0GlVs/9cVSyPYXdcSF" crossorigin="anonymous">
         <style>
         h3, h2, h1{
          text-align: center;
    
        }
         </style>
     
     <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap-theme.min.css">
     <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js"></script>
     <style type="text/css"> a { text-decoration:none }</style>
     </head>
     <body>
     <div class="menu-container">
<ul class="vertical-nav">
 <li>
        <a class="naver-icon" href="https://www.joongbu.ac.kr/" target="_blank"><img src="/image/중부대학교.png" width="60"></a>

 </li>
 <li>
   <a href="#"><svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-person-plus" viewBox="0 0 16 16">
<path d="M6 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H1s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C9.516 10.68 8.289 10 6 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z"/>
<path fill-rule="evenodd" d="M13.5 5a.5.5 0 0 1 .5.5V7h1.5a.5.5 0 0 1 0 1H14v1.5a.5.5 0 0 1-1 0V8h-1.5a.5.5 0 0 1 0-1H13V5.5a.5.5 0 0 1 .5-.5z"/>
</svg>내 정보</a>
   <div class="hover-menu">
     <ul>
       <li><a href="/logout">로그아웃</a></li>
       <li><a href="/member_data">진단결과</a></li>
       
     </ul>
   </div>
 </li>
 <li>
   <a href="/profile"><svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-people-fill" viewBox="0 0 16 16">
<path d="M7 14s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1H7zm4-6a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/>
<path fill-rule="evenodd" d="M5.216 14A2.238 2.238 0 0 1 5 13c0-1.355.68-2.75 1.936-3.72A6.325 6.325 0 0 0 5 9c-4 0-5 3-5 4s1 1 1 1h4.216z"/>
<path d="M4.5 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z"/>
</svg>제작자<br>프로필</a>
   

 <li class="log-out">
   <a title="홈페이지" href="/"><svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-house-door" viewBox="0 0 16 16">
<path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4.5a.5.5 0 0 0 .5-.5v-4h2v4a.5.5 0 0 0 .5.5H14a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146zM2.5 14V7.707l5.5-5.5 5.5 5.5V14H10v-4a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v4H2.5z"/>
</svg></a>
 </li>
</ul>
</div>
<br><br><h1><font size=20>진단 결과</font></h1><br><br>
<div style="width:1300px; height:600px; display:block; margin: 0px auto; overflow:auto;">
<h3><table  class="table table-striped"></h3>
  <thead>
    <tr>
      <th stylescope="col">#</th>
      <th width="10% scope="col">항목</th>
      <th width="10% scope="col">결과</th>
      <th scope="col">정보</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">1</th>
      <td><a href='/XSS'>XSS</td></a>
      <td>${XSS}</td>
      <td>${XSS_info}</td>
    </tr>
    <tr>
      <th scope="row">2</th>
      <td><a href='/SQLINJECTION'>SQL INJECTION</td></a>
      <td>${sqlin}</td>
      <td>${sql_info}</td>
    </tr>
    <tr>
      <th scope="row">3</th>
      <td><a href='/CSRF'>CSRF</td></a>
      <td>${CSRF}</td>
      <td>${CSRF_info}</td>
    </tr>
    <tr>
      <th scope="row">4</th>
      <td><a href='/BRUTE'>BruteForce</td></a>
      <td>${bruteForce}</td>
      <td>${bruteForce_info}</td>
    </tr>
    <tr>
      <th scope="row">5</th>
      <td><a href='/PLAIN'>Plaintext</td></a>
      <td>${sniff}</td>
      <td>${http_info}</td>
    </tr>
    <tr>
      <th scope="row">6</th>
      <td><a href='/COOKIE'>Cookie</td></a>
      <td>${cookie}</td>
      <td>${cookie_info}</td>
    </tr>
    <tr>
      <th scope="row">7</th>
      <td><a href='/SNIFF'>Redircet</td></a>
      <td>${sessionVul}</td>
    </tr>
    <tr>
      <th scope="row">8</th>
      <td><a href='/SESSION'>Session</td></a>
      <td>${http}</td>
      <td></td>
    </tr>
    <tr>
      <th scope="row">9</th>
      <td><a href='/LOCAL'>Sensitive Data Exposure</td></a>
      <td colspan="2" >${base64Vul}</td>
    </tr>
    </tbody>
</table>
</div>
         <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-kQtW33rZJAHjgefvhyyzcGF3C5TFyBQBA13V1RKPf4uH+bwyzQxZ6CmMZHmNBEfJ" crossorigin="anonymous"></script>
      </body>
      </html> 
      `;
  },
}
