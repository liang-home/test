package com.tongjiao.service.util;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import com.tongjiao.common.exception.BaseException;
import com.tongjiao.common.result.ResultCode;
import com.tongjiao.pojo.PreSecurityUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * @Classname JwtUtil
 * @Description JWT工具类
 * @Author 
 * @Date 2019-05-07 09:23
 * @Version 1.0
 */
@Component
public class JwtUtil {

	/** 用户名称 */
	private static final String USERNAME = Claims.SUBJECT;
	/**  */
	private static final String USERID = "userid";
	/** 创建时间 */
	private static final String CREATED = "created";
	/** 权限列表 */
	private static final String AUTHORITIES = "authorities";
	/** 密钥 */
	private static final String SECRET = "abcdefgh";
	/** 有效期3小时 */
	private static final long EXPIRE_TIME = 12 * 60 * 60 * 1000;
	/**  */
	private static final String DEPTID = "deptid";

	// @Value("${jwt.header}")Authorization
	private String tokenHeader = "Authorization";

	// @Value("${jwt.tokenHead}")
	private String authTokenStart = "Bearer";

	/**
	 * @Title 生成令牌
	 * @Description 
	 * @param 
	 * @return String 令牌
	 * @throws
	 */
	public static String generateToken(PreSecurityUser userDetail) {
		Map<String, Object> claims = new HashMap<>(3);
		claims.put(USERID, userDetail.getUserId());
		claims.put(USERNAME, userDetail.getUsername());
		claims.put(DEPTID, userDetail.getDeptId());
		claims.put(CREATED, new Date());
		claims.put(AUTHORITIES, userDetail.getAuthorities());
		return generateToken(claims);
	}

	/**
	 * @Title 从数据声明生成令牌
	 * @Description 
	 * @param claims 数据声明
	 * @return String 令牌
	 * @throws
	 */
	private static String generateToken(Map<String, Object> claims) {
		Date expirationDate = new Date(System.currentTimeMillis() + EXPIRE_TIME);
		return Jwts.builder().setClaims(claims).setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512, SECRET).compact();
	}

	/**
	 * @Title 从令牌中获取用户名
	 * @Description 
	 * @param 令牌
	 * @return String 用户名
	 * @throws
	 */
	public static String getUsernameFromToken(String token) {
		Claims claims = getClaimsFromToken(token);
		return claims.getSubject();
	}

	/**
	 * @Title 根据请求令牌获取登录认证信息
	 * @Description 
	 * @param 
	 * @return PreSecurityUser 用户
	 * @throws
	 */
	public PreSecurityUser getUserFromToken(HttpServletRequest request) {
		// 获取请求携带的令牌
		String token = getToken(request);
		
		/*
		 * if (StringUtils.isBlank(token)) { throw new
		 * BaseException(ResultCode.PARAM_IS_BLANK); }
		 */
		
		token = "eyJhbG" + token;
		
		Claims claims = getClaimsFromToken(token);
		if (claims == null) {
			return null;
		}
		String username = claims.getSubject();
		if (username == null) {
			return null;
		}
		if (isTokenExpired(token)) {
			return null;
		}
		// 解析对应的权限以及用户id
		Object authors = claims.get(AUTHORITIES);
		Integer userId = (Integer) claims.get(USERID);
		Integer deptId = (Integer) claims.get(DEPTID);
		Set<String> perms = new HashSet<>();
		if (authors instanceof List) {
			for (Object object : (List) authors) {
				perms.add(((Map) object).get("authority").toString());
			}
		}
		Collection<? extends GrantedAuthority> authorities = AuthorityUtils
				.createAuthorityList(perms.toArray(new String[0]));
		if (validateToken(token, username)) {
			// 未把密码放到jwt
			return new PreSecurityUser(userId, deptId, username, "", authorities, null);
		}
		return null;
	}
	
	/**
	 * @Title 根据令牌获取认证信息
	 * @Description 
	 * @param token 令牌
	 * @return PreSecurityUser 用户
	 * @throws
	 */
	public static PreSecurityUser getUserFromToken(String token) {
		// 获取请求携带的令牌
		if (StringUtils.isNotEmpty(token)) {
			Claims claims = getClaimsFromToken(token);
			if (claims == null) {
				return null;
			}
			String username = claims.getSubject();
			if (username == null) {
				return null;
			}
			if (isTokenExpired(token)) {
				// return null;
			}
			// 解析对应的权限以及用户id
			Object authors = claims.get(AUTHORITIES);
			Integer userId = (Integer) claims.get(USERID);
			Integer deptId = (Integer) claims.get(DEPTID);
			Set<String> perms = new HashSet<>();
			if (authors instanceof List) {
				for (Object object : (List) authors) {
					perms.add(((Map) object).get("authority").toString());
				}
			}
			Collection<? extends GrantedAuthority> authorities = AuthorityUtils
					.createAuthorityList(perms.toArray(new String[0]));
			if (validateToken(token, username)) {
				// 未把密码放到jwt
				return new PreSecurityUser(userId, deptId, username, "", authorities, null);
			}
		}
		return null;
	}

	/**
	 * @Title 从令牌中获取数据声明
	 * @Description 
	 * @param token 令牌
	 * @return Claims 数据声明
	 * @throws
	 */
	private static Claims getClaimsFromToken(String token) {
		Claims claims;
		try {
			claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			claims = null;
		}
		return claims;
	}

	/**
	 * @Title 验证令牌
	 * @Description 
	 * @param token 令牌
	 * @param username 用户名
	 * @return Boolean
	 * @throws
	 */
	private static Boolean validateToken(String token, String username) {
		String userName = getUsernameFromToken(token);
		return (userName.equals(username) && !isTokenExpired(token));
	}

	/**
	 * @Title 刷新令牌
	 * @Description 
	 * @param tokne
	 * @return String
	 * @throws
	 */
	public static String refreshToken(String token) {
		String refreshedToken;
		try {
			Claims claims = getClaimsFromToken(token);
			claims.put(CREATED, new Date());
			refreshedToken = generateToken(claims);
		} catch (Exception e) {
			refreshedToken = null;
		}
		return refreshedToken;
	}

	/**
	 * @Title 判断令牌是否过期
	 * @Description 
	 * @param token 令牌
	 * @return Boolean 是否过期
	 * @throws
	 */
	private static Boolean isTokenExpired(String token) {
		try {
			Claims claims = getClaimsFromToken(token);
			Date expiration = claims.getExpiration();
			return expiration.before(new Date());
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * @Title 获取请求token
	 * @Description 
	 * @param 
	 * @return String
	 * @throws
	 */
	public String getToken(HttpServletRequest request) {
		String token = request.getHeader(tokenHeader);
		if (StringUtils.isNotEmpty(token)) {
			token = token.substring(authTokenStart.length());
		}
		return token;
	}
    


	public static void main(String[] args) {

		String token = "eyJhbGciOiJIUzUxMiJ9.eyJkZXB0aWQiOjYsInN1YiI6ImFkbWluIiwiZXhwIjoxNTY3NDMzNzkyLCJ1c2VyaWQiOjQsImNyZWF0ZWQiOjE1Njc0MzAxOTIwOTQsImF1dGhvcml0aWVzIjpbeyJhdXRob3JpdHkiOiJzeXM6bWVudTp1cGRhdGUifSx7ImF1dGhvcml0eSI6InN5czptZW51OmRlbGV0ZSJ9LHsiYXV0aG9yaXR5Ijoic3lzOmRlcHQ6dXBkYXRlIn0seyJhdXRob3JpdHkiOiJzeXM6am9iOmFkZCJ9LHsiYXV0aG9yaXR5IjoibWFuYWdlOmdvbmdHYW9aaG9uZ1hpbiJ9LHsiYXV0aG9yaXR5Ijoic3lzOnVzZXI6dXBkYXRlRW1haWwifSx7ImF1dGhvcml0eSI6Im1hbmFnZTpzYWlTaGlHdWFuTGk6bXlNYW5hZ2VyU2FpU2hpIn0seyJhdXRob3JpdHkiOiJST0xFXzUifSx7ImF1dGhvcml0eSI6InN5czptZW51OmFkZCJ9LHsiYXV0aG9yaXR5Ijoic3lzOnVzZXI6YWRkIn0seyJhdXRob3JpdHkiOiJzeXM6ZGVwdDpkZWxldGUifSx7ImF1dGhvcml0eSI6InN5czpsb2c6dmlldyJ9LHsiYXV0aG9yaXR5Ijoic3lzOnJvbGU6dmlldyJ9LHsiYXV0aG9yaXR5Ijoic3lzOmpvYjpkZWxldGUifSx7ImF1dGhvcml0eSI6InN5czpsb2c6ZGVsZXRlIn0seyJhdXRob3JpdHkiOiJzeXM6dXNlcjpkZWxldGUifSx7ImF1dGhvcml0eSI6InN5czpkZXB0OnZpZXcifSx7ImF1dGhvcml0eSI6InN5czpqb2I6dmlldyJ9LHsiYXV0aG9yaXR5Ijoic3lzOmRpcHQ6dmlldyJ9LHsiYXV0aG9yaXR5Ijoic3lzOnVzZXI6dXBkYXRlIn0seyJhdXRob3JpdHkiOiJzeXM6bWVudTp2aWV3In0seyJhdXRob3JpdHkiOiJzeXM6cm9sZTphZGQifSx7ImF1dGhvcml0eSI6Im1hbmFnZXI6dG91R2FvU2hlbkhlIn0seyJhdXRob3JpdHkiOiJzeXM6dXNlcjp2aWV3In0seyJhdXRob3JpdHkiOiJtYW5hZ2VyOnNhaVNoaUd1YW5MaTpteXNlbGZTYWlTaGkifSx7ImF1dGhvcml0eSI6Im1hbmFnZXI6YWN0aXZlbWFuYWdlIn0seyJhdXRob3JpdHkiOiJzeXM6dXNlcjp1cGRhdGVQYXNzIn0seyJhdXRob3JpdHkiOiJtYW5hZ2U6c2FpU2hpR3VhbkxpIn0seyJhdXRob3JpdHkiOiJzeXM6c29jaWFsOnVudGllZCJ9LHsiYXV0aG9yaXR5IjoibWFuYWdlcjpndWFuRmFuZ0ZhQnUifSx7ImF1dGhvcml0eSI6InN5czpqb2I6dXBkYXRlIn0seyJhdXRob3JpdHkiOiJtYW5hZ2VyOnNhaVNoaUdhbkxpOnNhbll1RGVTYWlTaGkifSx7ImF1dGhvcml0eSI6InN5czpyb2xlOnVwZGF0ZSJ9LHsiYXV0aG9yaXR5Ijoic3lzOmNvZGVnZW46Y29kZWdlbiJ9LHsiYXV0aG9yaXR5Ijoic3lzOnNvY2lhbDp2aWV3In0seyJhdXRob3JpdHkiOiJzeXM6ZGVwdDphZGQifSx7ImF1dGhvcml0eSI6InN5czpyb2xlOmRlbGV0ZSJ9LHsiYXV0aG9yaXR5IjoibWFuYWdlcjpiYW5LdWFpR29uZ0dhbyJ9XX0.6NqY3Geq42fwtwhLru0OCB-LYP-YzWcm_pB7QiDwGx-ujMBzrzuNgGrC40DeNqYU2KjT6ArLvVn9z1pKW9m9kA";
		token = "eyJhbGciOiJIUzUxMiJ9.eyJkZXB0aWQiOjYsInN1YiI6ImFkbWluIiwiZXhwIjoxNTY3NTA2MTg5LCJ1c2VyaWQiOjQsImNyZWF0ZWQiOjE1Njc1MDI1ODk0NDEsImF1dGhvcml0aWVzIjpbeyJhdXRob3JpdHkiOiJzeXM6bWVudTp1cGRhdGUifSx7ImF1dGhvcml0eSI6InN5czptZW51OmRlbGV0ZSJ9LHsiYXV0aG9yaXR5Ijoic3lzOmRlcHQ6dXBkYXRlIn0seyJhdXRob3JpdHkiOiJzeXM6am9iOmFkZCJ9LHsiYXV0aG9yaXR5IjoibWFuYWdlOmdvbmdHYW9aaG9uZ1hpbiJ9LHsiYXV0aG9yaXR5Ijoic3lzOnVzZXI6dXBkYXRlRW1haWwifSx7ImF1dGhvcml0eSI6Im1hbmFnZTpzYWlTaGlHdWFuTGk6bXlNYW5hZ2VyU2FpU2hpIn0seyJhdXRob3JpdHkiOiJST0xFXzUifSx7ImF1dGhvcml0eSI6InN5czptZW51OmFkZCJ9LHsiYXV0aG9yaXR5Ijoic3lzOnVzZXI6YWRkIn0seyJhdXRob3JpdHkiOiJzeXM6ZGVwdDpkZWxldGUifSx7ImF1dGhvcml0eSI6InN5czpsb2c6dmlldyJ9LHsiYXV0aG9yaXR5Ijoic3lzOnJvbGU6dmlldyJ9LHsiYXV0aG9yaXR5Ijoic3lzOmpvYjpkZWxldGUifSx7ImF1dGhvcml0eSI6InN5czpsb2c6ZGVsZXRlIn0seyJhdXRob3JpdHkiOiJzeXM6dXNlcjpkZWxldGUifSx7ImF1dGhvcml0eSI6InN5czpkZXB0OnZpZXcifSx7ImF1dGhvcml0eSI6InN5czpqb2I6dmlldyJ9LHsiYXV0aG9yaXR5Ijoic3lzOmRpcHQ6dmlldyJ9LHsiYXV0aG9yaXR5Ijoic3lzOnVzZXI6dXBkYXRlIn0seyJhdXRob3JpdHkiOiJzeXM6bWVudTp2aWV3In0seyJhdXRob3JpdHkiOiJzeXM6cm9sZTphZGQifSx7ImF1dGhvcml0eSI6Im1hbmFnZXI6dG91R2FvU2hlbkhlIn0seyJhdXRob3JpdHkiOiJzeXM6dXNlcjp2aWV3In0seyJhdXRob3JpdHkiOiJtYW5hZ2VyOnNhaVNoaUd1YW5MaTpteXNlbGZTYWlTaGkifSx7ImF1dGhvcml0eSI6Im1hbmFnZXI6d29EZVRvdUdhbyJ9LHsiYXV0aG9yaXR5IjoibWFuYWdlcjphY3RpdmVtYW5hZ2UifSx7ImF1dGhvcml0eSI6InN5czp1c2VyOnVwZGF0ZVBhc3MifSx7ImF1dGhvcml0eSI6Im1hbmFnZTpzYWlTaGlHdWFuTGkifSx7ImF1dGhvcml0eSI6InN5czpzb2NpYWw6dW50aWVkIn0seyJhdXRob3JpdHkiOiJtYW5hZ2VyOmd1YW5GYW5nRmFCdSJ9LHsiYXV0aG9yaXR5Ijoic3lzOmpvYjp1cGRhdGUifSx7ImF1dGhvcml0eSI6Im1hbmFnZXI6c2FpU2hpR2FuTGk6c2FuWXVEZVNhaVNoaSJ9LHsiYXV0aG9yaXR5Ijoic3lzOnJvbGU6dXBkYXRlIn0seyJhdXRob3JpdHkiOiJzeXM6Y29kZWdlbjpjb2RlZ2VuIn0seyJhdXRob3JpdHkiOiJzeXM6c29jaWFsOnZpZXcifSx7ImF1dGhvcml0eSI6InN5czpkZXB0OmFkZCJ9LHsiYXV0aG9yaXR5Ijoic3lzOnJvbGU6ZGVsZXRlIn0seyJhdXRob3JpdHkiOiJtYW5hZ2VyOmJhbkt1YWlHb25nR2FvIn1dfQ.XUQ6p7fiEcdH_XdOwUwuUmt77IQ3KjextsSw_dp3thAFigHk2LqfyJTxtey4GVA2fUl4cZ83bxgUvETzq8suHw";
		String ss = JwtUtil.getUserFromToken(token).getUsername();
		String ss2 = JwtUtil.getUserFromToken(token).getDeptId() + "";
		System.out.println(ss2);

	}

}
