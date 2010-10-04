<?php
/**
 * OpenIDとAuthを利用したコンポーネント for CakePHP
 * @author polidog
 * @version 0.1
 */
class AuthOpenidComponent extends Object {
	
	public $components = array('Auth','Openid','Session');
	
	private $controller = null;
	

	
	/**
	 * ユーザーモデル名
	 * @var string
	 * @access public
	 */
	public $userModel = 'User';
	
	/**
	 * ユーザー名、パスワード、有効フラグ
	 * @var array
	 * @access public
	 */
	public $fileds =  array('username' => 'username', 'password' => 'password','enable' => 'enable');
	
	/**
	 * ログイン後のリダイレクト先
	 * @var string
	 * @access public
	 */
	public $loginRedirect = '/users/index';
	
	/**
	 * OpenId認証をキャンセルした場合のリダイレクト先
	 * @var string
	 * @access public
	 */
	public $cancelRedirect = '/users/login';
	
	public $cancelMessage = 'Verification cancelled';
	
	/**
	 * 使用しているサーバのドメイン名
	 * @var string
	 * @access public
	 */
	public $host = null;
	
	/**
	 * 通信方法
	 * @var string http|https
	 * @access public
	 */
	public $protocol = "http";
	
	/**
	 * Oepn idの認証URLを指定する
	 * @var string
	 * @access public
	 */
	public $openidUrl = "https://mixi.jp";
	
	/**
	 * Openid authenticate callback action use url
	 * @var string
	 * @access public
	 */
	public $returnTo	= "/users/login";
	
	/**
	 * Openid  authenticate params
	 * @var unknown_type
	 */
	public $realm		= null;
	
	/**
	 * ログイン処理をするアクションを指定
	 * @var string
	 * @access public
	 */
	public $loginAction = '/users/login';
	
	public $autoRedirect = true;
	
	/**
	 * サーバ証明書ファイルのパスの指定
	 * @var string
	 */
	public $openidPem = null;
	

	
	function initialize($controller,$settings) {
		$this->controller = $controller;
		
		$this->Auth->userModel = $this->userModel;
		$this->Auth->fields = array('username' => $this->fileds['username'], 'password' => $this->fileds['password']);
		
		$this->Auth->userScope = array($this->_createFiled($this->userModel, 'enable') => 1);
		
		$this->Auth->loginAction = null;
		$this->Auth->logoutAction = null;
	}
	
	function startup(&$controller) {
		$GLOBALS['openid_pem'] = $this->openidPem;
		$this->Auth->autoRedirect = $this->autoRedirect;
		if ( is_null( $this->host) ) {
			$this->host = env('HTTP_HOST');
		}
		
		if ( is_null($this->returnTo) ) {
			$this->returnTo = $this->protocol."://".$this->host.$this->loginAction;
		}else {
			$this->returnTo = $this->protocol."://".$this->host.$this->returnTo;
		}
		
		if ( is_null( $this->realm ) ) {
			$this->realm = $this->protocol.'://'.$this->host;
		}
				
		$isErrorOrTests = (
			strtolower($controller->name) == 'cakeerror' ||
			(strtolower($controller->name) == 'tests' && Configure::read() > 0)
		);
		if ($isErrorOrTests) {
			return true;
		}
		
		$methods = array_flip($controller->methods);
		$action = strtolower($controller->params['action']);
		$isMissingAction = (
			$controller->scaffold === false &&
			!isset($methods[$action])
		);

		if ($isMissingAction) {
			return true;
		}
				
		$url = '';
		if (isset($controller->params['url']['url'])) {
			$url = $controller->params['url']['url'];
		}
		$url = Router::normalize($url);
		$loginAction = Router::normalize($this->loginAction);
		$allowedActions = array_map('strtolower', $this->Auth->allowedActions);
		$isAllowed = (
			$this->Auth->allowedActions == array('*') ||
			in_array($action, $allowedActions)
		);
		
		if ( $loginAction != $url && $isAllowed ) {
			return true;
		}
		
		if ( $loginAction == $url ) {
			$this->login();
		}
		
	}
	
	/**
	 * ログイン処理
	 * @param string $openidUrl
	 * @param string $returnTo
	 * @param string $realm
	 * @param array $dataFields
	 */
	public function login($openidUrl = null, $returnTo = null , $realm = null , $dataFields = null) {
		
		if ( is_null($openidUrl) ) {
			$openidUrl = $this->openidUrl;
		}
		
		if ( is_null( $returnTo ) ) {
			$returnTo = $this->returnTo;
		}
		
		if ( is_null( $realm ) ) {
			$realm = $this->realm;
		}
		
		
		if ( !$this->Session->check('AuthOpenid.login_openid_check')) {
			
			try {
				$this->Session->write('AuthOpenid.login_openid_check',1);
				$this->Openid->authenticate($openidUrl,$returnTo,$realm,$dataFields);
			} catch (InvalidArgumentException $e) {
				$this->Session->delete('AuthOpenid.login_openid_check');
				$this->_setMessage('Invalid OpenID');
			} catch (Exception $e) {
				$this->Session->delete('AuthOpenid.login_openid_check');
				$this->_setMessage($e->getMessage());
			}
			
		} elseif ( $this->Session->read('AuthOpenid.login_openid_check') == 1 ) {
			$this->Session->delete('AuthOpenid.login_openid_check');
			$response = $this->Openid->getResponse($returnTo);

			switch( $response->status ) {
				case Auth_OpenID_CANCEL :
					//$this->_setMessage('Verification cancelled');
					$this->cancelOpenId();
					return false;
					break;
				case Auth_OpenID_FAILURE :
					$this->_setMessage('OpenID verification failed: '.$response->message);
					break;
				case Auth_OpenID_SUCCESS :
					$modelName = Inflector::camelize( $this->userModel );
					$user = $this->_getUserData($response->identity_url, $modelName );
					if ( !empty($user) ) {
						$data = array();
						$data[$modelName] = array(
							$this->fileds['username'] = $user[$modelName][$this->fileds['username']],
							$this->fileds['password'] = $user[$modelName][$this->fileds['password']]
						);
						return $this->authLogin($data,$modelName);
					} else {
						$user = $this->registerUser($response->identity_url);

						if ( $user ) {
							if ( isset($user[$this->fileds['enable']]) ) {
								unset($user[$this->fileds['enable']]);
							}
							$this->authLogin($user,$modelName);
						}
					}
					break;
			}
		}
		
	}
	
	/**
	 * ログアウト処理を行う
	 */
	public function logout() {
		$this->Auth->logout();
	}
	
	
	/**
	 * Authコンポーネントのログイン処理
	 * @param array $data ログインデータの配列
	 * @param string $modelName　ユーザ情報を保持しているモデル名
	 */
	public function authLogin($data, $modelName = null) {
		if ( is_null( $modelName ) ) {
			$modelName = Inflector::camelize( $this->userModel );
		}

		$this->Auth->userScope = array($this->_createFiled($modelName,'enable') => 1);
		$this->Auth->login($data);
		if ( $this->loginRedirect ) {
			$this->redirect( $this->loginRedirect );
		}
		return true;
	}
	
	/**
	 * OpenIdを使って初めてログインした場合にデータを保存する
	 * @param $username ユーザー名(identity_url)
	 * @param $password パスワード(time())
	 * 
	 * @return mixed 保存できた場合はarray(保存したデータ)、失敗した場合はfalseが返る
	 */
	public function registerUser($username,$password=null, $modelName=null) {
		if ( is_null($password) ) {
			$password = time();
		}
		if ( is_null( $modelName ) ) {
			$modelName = Inflector::camelize( $this->userModel );
		}
		
		$model = $this->Auth->getModel($modelName);
		$savedata = array();
		$savedata[$modelName] = array(
			$this->fileds['username'] => $username,
			$this->fileds['password']  => $password,
			$this->fileds['enable']  => 1,
		);
		$model->create($savedata);
		if ( $model->validates() ) {
			if ( $model->save($savedata) ) {
				return $savedata;
			}
		}
		
		return false;		
	}
	
	/**
	 * Authコンポーネントのラッパー
	 * @param array $data
	 */
	public function allow( $data = array() ) {
		return $this->Auth->allow( $data );
	}
	/**
	 * ユーザーを検索する
	 * @param string $identity_url
	 * @return string 
	 */
	private function _getUserData( $identity_url, $modelName = null ) {
		if ( is_null( $modelName ) ) {
			$modelName = Inflector::camelize( $this->userModel );
		}
		$model = $this->Auth->getModel($modelName);
		
		return $model->find('first', 
			array(
				'conditions' => array($this->_createFiled($modelName,'username') => $identity_url,
								$this->_createFiled($modelName,'enable') => 1 ),
				'recursive' => -1
			)
		);
		
		
	}
	
	private function cancelOpenId() {
		$this->Auth->loginError = $this->cancelMessage;
		$this->controller->redirect($this->cancelRedirect);
	}
	
	/**
	 * User.idみたいな形のStringを生成する
	 * @param string $modelName
	 * @param string $filedName
	 */
	private function _createFiled($modelName,$filedName) {
		if (isset($this->fileds[$filedName])) {
			$filedName = $this->fileds[$filedName];
		}
		return $modelName.".".$filedName;
	} 
	
	
	/**
	 * controller set message
	 * @param string $message
	 */
	private function _setMessage($message) {
		$this->controller->set('message',$message);
	}
	
	
}