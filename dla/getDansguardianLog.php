<?php
/************************* CONFIGURATION *************************/
// Specify the path to dansguardian logs.
define('DANSGUARDIAN_LOG_PATH','/var/log/dansguardian');
/************************* CONFIGURATION *************************/
//
// # Log File Format
// # 1 = DansGuardian format (space delimited)
// # 2 = CSV-style format
// # 3 = Squid Log File Format
// # 4 = Tab delimited
// logfileformat = 1
?>
<?php
// Disble cached data
header('Cache-Control: no-cache, must-revalidate');
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');

$type = htmlspecialchars($_GET["type"]);
$start = htmlspecialchars($_GET["start"]);

define('TYPE_TAIL',1);
define('TYPE_SUMMARY',2);
define('TYPE_GRAPH',3);

switch( $type ) {
	case TYPE_TAIL:
		$dlr = new dansguardian_log_reader();
		try {
			$tail_r = $dlr->getTail($start);
			header('X-START: '.$tail_r['start']);
			foreach($tail_r['lines'] as $line) {
				echo $line;
			}
		} catch (Exception $e) {
			header('ERROR: '.$e->getMessage());
			http_response_code(500);
		}
		exit; // Avoid any extra characters to be printed
	case TYPE_SUMMARY:
		header('Content-type: application/json');
		$dlr = new dansguardian_log_reader();
		try {
			$data = $dlr->getSummary();

			$griddata = array(
				'identifier' => 'id',
				'label' => 'ip',
				'items' => $data
			);
			echo json_encode($griddata);
		} catch (Exception $e) {
			header('ERROR: '.$e->getMessage());
			echo 'ERROR: '.$e->getMessage();
			http_response_code(500);
		}
		exit; // Avoid any extra characters to be printed
	case TYPE_GRAPH:
		header('Content-type: application/json');
		$dlr = new dansguardian_log_reader();
		try {
			$data = $dlr->getSeries();

			echo json_encode($data);
		} catch (Exception $e) {
			header('ERROR: '.$e->getMessage());
			http_response_code(500);
		}
		exit; // Avoid any extra characters to be printed
	default:
		echo "No type specified";
		exit; // Avoid any extra characters to be printed
}


class dansguardian_log_reader
{
	private $file = FALSE;

	private $isGzip = FALSE;

	private $handle = null;
 
	public function getTail($start=0) {
		# Use default file
		$pos = $this->openFile('access.log', $start, 10);
		$lines = array();

		while (!$this->foundEOF()) {
			$lines[] = $this->getLine();
		}
		return array( lines => $lines, start => $pos);
	} 

	public function getSummary($filter='DENIED') {
		# Use default file
		$pos = $this->openFile('access.log');
		$lines = array();
		$linecount = 0;

		while (!$this->foundEOF()) {
			$data = $this->getDArray($this->getLine('/'.$filter.'/'), $linecount++);
			if( $data ) {
				$lines[] = $data;
			}
		}
		return $lines;
	} 

	public function getSeries() {
		# Use default file
		$pos = $this->openFile('access.log');
		$lines = array();
		$labels = array();
		$labels_t = array();
		$linecount = 0;
		$date = null;

		while (!$this->foundEOF()) {
			$data = $this->getLine();
			preg_match("/^([^ ]+) (\d+:\d+):\d+ /", $data, $matches); // pattern to format the line
			if( isset($matches[0]) ) {
				//
				if(!$date) {
					$date = $matches[1];
					$start_time = $matches[2];
				}
				$time = $matches[2];
				$lines["$time"] += 1;
				$end_time = $time;
			}
		}

		$counter = 0;
		$temp_time = $start_time;
		$start_time_r = preg_split("/:/", $temp_time);
		do {
			$labels_t["$temp_time"] = $counter;
			$temp_time = date("G:i", mktime($start_time_r[0],$start_time_r[1]+$counter));
			$counter++;
		} while( $temp_time != $end_time );

		$series = array_fill(0, $counter, 0);
		foreach ($lines as $key => $value) {
			$series[intval($labels_t[$key])] = $value;
		}
		foreach ($labels_t as $key => $value) {
			$labels[] = array( "value" => $value, "text" => $key );
		}
		return array(labels => array( labels => $labels ), series => array( data => $series ) );
	} 

	private function openFile($filename, $start=0, $tailnum=0) {
		$this->file = DANSGUARDIAN_LOG_PATH . "/" . $filename;
		$this->getFileHandle();
		if( $start ) {
			$this->seekFile($start);
		} else if( $tailnum ) {
			$this->seekLine($tailnum);
		}
		return $this->getHandlePos();
	}

	private function getFileHandle() {
		if( preg_match("/\.gz$/", $this->file) ) {
			$this->isGzip = TRUE;
			$this->handle = gzopen($this->file, 'rb');
		} else {
			$this->handle = fopen($this->file, 'rb');
		}
		if( !$this->handle ) {
			throw new Exception("Error opening " . $this->file);
		}
	}

	private function seekFile($start) {
		if( $this->isGzip ) {
			gzseek($this->handle, $start);
		} else {
			fseek($this->handle, $start);
		}
	}

	private function seekLine($tailnum) {
		$fifo_count = -1;
		$fifo_overflow = false;
		$lineset = array();
		$lineset[-1] = 0; // Workaround for files with one or less lines
		while (!$this->foundEOF()) {
			$fifo_count = $this->nextFifoNumber($fifo_count, $tailnum);
			$lineset[$fifo_count] = $this->getHandlePos();
			$this->getLine();

			// We got more than $tailnum lines
			if( $fifo_count == $tailnum ) {
				$fifo_overflow = true;
			}
		}

		// Set handle pointer to position before linecount - $tailnum
		if( $fifo_overflow ) {
			$fifo_count = $this->nextFifoNumber($fifo_count, $tailnum);
		} else {
			$fifo_count--;
		}

		if( $this->isGzip ) {
			gzseek($this->handle, $lineset[$fifo_count]);
		} else {
			fseek($this->handle, $lineset[$fifo_count]);
		}
	}

	private function getLine($filter=null) {
		$line = null;
		if( $this->isGzip ) {
			$line = gzgets($this->handle);
		} else {
			$line = fgets($this->handle);
		}
		if( !$filter || preg_match($filter, $line) ) {
			return $line;
		}
		return null;
	}

	private function getHandlePos() {
		if( $this->isGzip ) {
			return gztell($this->handle);
		} else {
			return ftell($this->handle);
		}
	}

	private function foundEOF() {
		if( $this->isGzip ) {
			return gzfeof($this->handle);
		} else {
			return feof($this->handle);
		}
	}

	private function nextFifoNumber($cur_num, $max_num) {
		$cur_num++;
		if( $cur_num > $max_num ) {
			return 0;
		}
		return $cur_num;
	}

	private function getDArray($line, $count=0)
	{
		preg_match("/([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) /", $line, $matches); // pattern to format the line

		// Return false if no matches
		if(!isset($matches[0])) {
			return false;
		}
 
		$row = array();
		$row['id'] = $count;
		$row['datetime'] = preg_replace("/\./", "-", $matches[1]) . " " . $matches[2];
		$row['user'] = $matches[3];
		$row['ip'] = $matches[4];
		$row['url'] = $matches[5];
		$row['filter'] = $matches[6];

		return $row;
	}
}
?>
