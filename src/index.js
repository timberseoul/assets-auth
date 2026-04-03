export default {                                                                                                                
    async fetch(request, env) {                                                                                                   
      const url = new URL(request.url);                                                                                           
      const method = request.method.toUpperCase();                                                                                
                                                                                                                                  
      // 1) 只允许 GET/HEAD，拒绝其他方法                                                                                         
      if (method !== "GET" && method !== "HEAD") {                                                                                
        return new Response("Method Not Allowed", { status: 405 });                                                               
      }                                                                                                                           
                                                                                                                                  
      // 2) 解析路径和签名参数                                                                                                    
      const path = decodeURIComponent(url.pathname); // 例: /posts/gitmerge.webp                                                  
      const exp = url.searchParams.get("exp");                                                                                    
      const sig = url.searchParams.get("sig");                                                                                    
                                                                                                                                  
      // 3) 参数缺失直接拒绝                                                                                                      
      if (!exp || !sig) return new Response("Forbidden", { status: 403 });                                                        
                                                                                                                                  
      // 4) 过期校验                                                                                                              
      const now = Math.floor(Date.now() / 1000);                                                                                  
      const expNum = Number(exp);                                                                                                 
      if (!Number.isFinite(expNum) || expNum < now) {                                                                             
        return new Response("Expired", { status: 403 });                                                                          
      }                                                                                                                           
                                                                                                                                  
      // 5) 签名校验：payload 必须和签发端完全一致                                                                                
      const payload = `${path}\n${exp}`;                                                                                          
      const ok = await verifyHmacSha256Hex(payload, sig, env.SIGNING_SECRET);                                                     
      if (!ok) return new Response("Bad signature", { status: 403 });                                                             
                                                                                                                                  
      // 6) 从 R2 读取对象                                                                                                        
      const key = path.replace(/^\/+/, ""); // posts/gitmerge.webp                                                                
      const object = await env.ASSETS_BUCKET.get(key);                                                                            
      if (!object) return new Response("Not Found", { status: 404 });                                                             
                                                                                                                                  
      // 7) 返回对象，并设置缓存头                                                                                                
      const headers = new Headers();                                                                                              
      object.writeHttpMetadata(headers);                                                                                          
      headers.set("ETag", object.httpEtag);                                                                                       
      headers.set("Cache-Control", "public, max-age=31536000, immutable");                                                        
      headers.set("X-Content-Type-Options", "nosniff");                                                                           
                                                                                                                                  
      if (method === "HEAD") return new Response(null, { status: 200, headers });                                                 
      return new Response(object.body, { status: 200, headers });                                                                 
    },                                                                                                                            
  };                                                                                                                              
                                                                                                                                  
  async function verifyHmacSha256Hex(data, sigHex, secret) {                                                                      
    const enc = new TextEncoder();                                                                                                
    const key = await crypto.subtle.importKey(                                                                                    
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const mac = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    const hex = [...new Uint8Array(mac)].map(b => b.toString(16).padStart(2, "0")).join("");
    return timingSafeEqual(hex, sigHex.toLowerCase());
  }

  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return r === 0;
  }