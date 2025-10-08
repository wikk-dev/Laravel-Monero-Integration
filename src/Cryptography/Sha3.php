<?php

namespace App\Cryptography;

use Error;
use Exception;

class Sha3
{
    const SHA3_224 = 1;
    const SHA3_256 = 2;
    const SHA3_384 = 3;
    const SHA3_512 = 4;

    const SHAKE128 = 5;
    const SHAKE256 = 6;

    const KECCAK_256 = 7;

    public static function init($type = null)
    {
        switch ($type) {
            case self::SHA3_224:
                return new self(1152, 448, 0x06, 28);
            case self::SHA3_256:
                return new self(1088, 512, 0x06, 32);
            case self::SHA3_384:
                return new self(832, 768, 0x06, 48);
            case self::SHA3_512:
                return new self(576, 1024, 0x06, 64);
            case self::SHAKE128:
                return new self(1344, 256, 0x1f);
            case self::SHAKE256:
                return new self(1088, 512, 0x1f);
            case self::KECCAK_256:
                return new self(1088, 512, 0x01, 32);
        }

        throw new Exception("Invalid operation type");
    }

    public function absorb($data)
    {
        if (self::PHASE_INPUT != $this->phase) {
            throw new Exception("No more input accepted");
        }

        $rateInBytes = $this->rateInBytes;
        $this->inputBuffer .= $data;
        while (strlen($this->inputBuffer) >= $rateInBytes) {
            list($input, $this->inputBuffer) = [
                substr($this->inputBuffer, 0, $rateInBytes),
                substr($this->inputBuffer, $rateInBytes),
            ];

            $blockSize = $rateInBytes;
            for ($i = 0; $i < $blockSize; $i++) {
                $this->state[$i] = $this->state[$i] ^ $input[$i];
            }

            $this->state = self::keccakF1600Permute($this->state);
            $this->blockSize = 0;
        }

        return $this;
    }

    public function squeeze($length = null)
    {
        $outputLength = $this->outputLength; // fixed length output
        if ($length && 0 < $outputLength && $outputLength != $length) {
            throw new Exception("Invalid length");
        }

        if (self::PHASE_INPUT == $this->phase) {
            $this->finalizeInput();
        }

        if (self::PHASE_OUTPUT != $this->phase) {
            throw new Exception("No more output allowed");
        }
        if (0 < $outputLength) {
            $this->phase = self::PHASE_DONE;
            return $this->getOutputBytes($outputLength);
        }

        $blockLength = $this->rateInBytes;
        list($output, $this->outputBuffer) = [
            substr($this->outputBuffer, 0, $length),
            substr($this->outputBuffer, $length),
        ];
        $neededLength = $length - strlen($output);
        $diff = $neededLength % $blockLength;
        if ($diff) {
            $readLength =
                (($neededLength - $diff) / $blockLength + 1) * $blockLength;
        } else {
            $readLength = $neededLength;
        }

        $read = $this->getOutputBytes($readLength);
        $this->outputBuffer .= substr($read, $neededLength);
        return $output . substr($read, 0, $neededLength);
    }

    // internally used
    const PHASE_INIT = 1;
    const PHASE_INPUT = 2;
    const PHASE_OUTPUT = 3;
    const PHASE_DONE = 4;

    private $phase = self::PHASE_INIT;
    private $state; // byte array (string)
    private $rateInBytes; // positive integer
    private $suffix; // 8-bit unsigned integer
    private $inputBuffer = ""; // byte array (string): max length = rateInBytes
    private $outputLength = 0;
    private $outputBuffer = "";

    public function __construct($rate, $capacity, $suffix, $length = 0)
    {
        if (1600 != $rate + $capacity) {
            throw new Error("Invalid parameters");
        }
        if (0 != $rate % 8) {
            throw new Error("Invalid rate");
        }

        $this->suffix = $suffix;
        $this->state = str_repeat("\0", 200);
        $this->blockSize = 0;

        $this->rateInBytes = $rate / 8;
        $this->outputLength = $length;
        $this->phase = self::PHASE_INPUT;
        return;
    }

    protected function finalizeInput()
    {
        $this->phase = self::PHASE_OUTPUT;

        $input = $this->inputBuffer;
        $inputLength = strlen($input);
        if (0 < $inputLength) {
            $blockSize = $inputLength;
            for ($i = 0; $i < $blockSize; $i++) {
                $this->state[$i] = $this->state[$i] ^ $input[$i];
            }

            $this->blockSize = $blockSize;
        }

        // Padding
        $rateInBytes = $this->rateInBytes;
        $this->state[$this->blockSize] = $this->state[$this->blockSize] ^ chr($this->suffix);
        if (($this->suffix & 0x80) != 0 &&$this->blockSize == $rateInBytes - 1) {
            $this->state = self::keccakF1600Permute($this->state);
        }
    
        $this->state[$rateInBytes - 1] =
            $this->state[$rateInBytes - 1] ^ "\x80";
        $this->state = self::keccakF1600Permute($this->state);
    }

    protected function getOutputBytes($outputLength)
    {
        // Squeeze
        $output = "";
        while (0 < $outputLength) {
            $blockSize = min($outputLength, $this->rateInBytes);
            $output .= substr($this->state, 0, $blockSize);
            $outputLength -= $blockSize;
            if (0 < $outputLength) {
                $this->state = self::keccakF1600Permute($this->state);
            }
        }

        return $output;
    }

    protected static function keccakF1600Permute($state)
    {
        $lanes = str_split($state, 8);
        $R = 1;
        $values = "\1\2\4\10\20\40\100\200";

        for ($round = 0; $round < 24; $round++) {
            // θ step
            $C = [];
            for ($x = 0; $x < 5; $x++) {
                // (x, 0) (x, 1) (x, 2) (x, 3) (x, 4)
                $C[$x] =
                    $lanes[$x] ^
                    $lanes[$x + 5] ^
                    $lanes[$x + 10] ^
                    $lanes[$x + 15] ^
                    $lanes[$x + 20];
            }
            for ($x = 0; $x < 5; $x++) {
                //$D = $C[($x + 4) % 5] ^ self::rotL64 ($C[($x + 1) % 5], 1);
                $D = $C[($x + 4) % 5] ^ self::rotL64One($C[($x + 1) % 5]);
                for ($y = 0; $y < 5; $y++) {
                    $idx = $x + 5 * $y; // x, y
                    $lanes[$idx] = $lanes[$idx] ^ $D;
                }
            }
            unset($C, $D);

            // ρ and π steps
            $x = 1;
            $y = 0;
            $current = $lanes[1]; // x, y
            for ($t = 0; $t < 24; $t++) {
                list($x, $y) = [$y, (2 * $x + 3 * $y) % 5];
                $idx = $x + 5 * $y;
                list($current, $lanes[$idx]) = [
                    $lanes[$idx],
                    self::rotL64($current, ((($t + 1) * ($t + 2)) / 2) % 64),
                ];
            }
            unset($temp, $current);

            // χ step
            $temp = [];
            for ($y = 0; $y < 5; $y++) {
                for ($x = 0; $x < 5; $x++) {
                    $temp[$x] = $lanes[$x + 5 * $y];
                }
                for ($x = 0; $x < 5; $x++) {
                    $lanes[$x + 5 * $y] =
                        $temp[$x] ^
                        (~$temp[($x + 1) % 5] & $temp[($x + 2) % 5]);
                }
            }
            unset($temp);

            // ι step
            for ($j = 0; $j < 7; $j++) {
                $R = (($R << 1) ^ (($R >> 7) * 0x71)) & 0xff;
                if ($R & 2) {
                    $offset = (1 << $j) - 1;
                    $shift = $offset % 8;
                    $octetShift = ($offset - $shift) / 8;
                    $n = "\0\0\0\0\0\0\0\0";
                    $n[$octetShift] = $values[$shift];

                    $lanes[0] = $lanes[0] ^ $n;
                    //^ self::rotL64 ("\1\0\0\0\0\0\0\0", (1 << $j) - 1);
                }
            }
        }

        return implode($lanes);
    }

    protected static function rotL64_64($n, $offset)
    {
        return ($n << $offset) & ($n >> 64 - $offset);
    }

    protected static function rotL64($n, $offset)
    {
        //$n = (binary) $n;
        //$offset = ((int) $offset) % 64;
        //if (8 != strlen ($n)) throw new Exception ('Invalid number');
        //if ($offset < 0) throw new Exception ('Invalid offset');

        $shift = $offset % 8;
        $octetShift = ($offset - $shift) / 8;
        $n = substr($n, -$octetShift) . substr($n, 0, -$octetShift);

        $overflow = 0x00;
        for ($i = 0; $i < 8; $i++) {
            $a = ord($n[$i]) << $shift;
            $n[$i] = chr((0xff & $a) | $overflow);
            $overflow = $a >> 8;
        }
        $n[0] = chr(ord($n[0]) | $overflow);
        return $n;
    }

    protected static function rotL64One($n)
    {
        list($n[0], $n[1], $n[2], $n[3], $n[4], $n[5], $n[6], $n[7]) = [
            chr(((ord($n[0]) << 1) & 0xff) ^ (ord($n[7]) >> 7)),
            chr(((ord($n[1]) << 1) & 0xff) ^ (ord($n[0]) >> 7)),
            chr(((ord($n[2]) << 1) & 0xff) ^ (ord($n[1]) >> 7)),
            chr(((ord($n[3]) << 1) & 0xff) ^ (ord($n[2]) >> 7)),
            chr(((ord($n[4]) << 1) & 0xff) ^ (ord($n[3]) >> 7)),
            chr(((ord($n[5]) << 1) & 0xff) ^ (ord($n[4]) >> 7)),
            chr(((ord($n[6]) << 1) & 0xff) ^ (ord($n[5]) >> 7)),
            chr(((ord($n[7]) << 1) & 0xff) ^ (ord($n[6]) >> 7)),
        ];
        return $n;
    }
}
