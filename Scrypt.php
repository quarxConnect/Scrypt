<?PHP

  /**
   * Copyright (c) 2018 Bernd Holzmüller <bernd@quarxconnect.de>
   * 
   * Permission is hereby granted, free of charge, to any person obtaining a copy
   * of this software and associated documentation files (the "Software"), to deal
   * in the Software without restriction, including without limitation the rights
   * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   * copies of the Software, and to permit persons to whom the Software is
   * furnished to do so, subject to the following conditions:
   * 
   * The above copyright notice and this permission notice shall be included in all
   * copies or substantial portions of the Software.
   * 
   * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   * SOFTWARE.
   **/
  
  class Scrypt {
    /* CPU/Memory cost parameter */
    private $N = 1024;
    
    /* Block size parameter */
    private $r = 1;
    
    /* Parallelization parameter */
    private $p = 1;
    
    /* Intended output length in octets of the derived key */
    private $dkLen = 32;
    
    /* PRNG-Function for pbkdf2 */
    private $PRNG = 'sha256';
    
    /* Calculated block-size */
    private $blockSize = 128;
    
    // {{{ __construct
    /**
     * Create a new scrypt-key-generator
     * 
     * @param int $N (optional)
     * @param int $r (optional)
     * @param int $p (optional)
     * @param int $dkLen (optional)
     * @param enum $PRNG (optional)
     * 
     * @access friendly
     * @return void
     **/
    function __construct ($N = 1024, $r = 1, $p = 1, $dkLen = 32, $PRNG = 'sha256') {
      $this->N = $N;
      $this->r = $r;
      $this->p = $p;
      $this->dkLen = $dkLen;
      $this->PRNG = $PRNG;
      $this->blockSize = $r * 128;
    }
    // }}}
    
    // {{{ __invoke
    /**
     * Derive an scrypt-key from given input and salt
     * 
     * @param string $Input
     * @param string $Salt
     * 
     * @access public
     * @return string
     **/
    function __invoke ($Input, $Salt) {
      $blockSize = $this->blockSize / 4;
      $X = array_values (unpack ('V' . ($this->p * $blockSize), $this->pbkdf2 ($Input, $Salt, 1, $this->blockSize * $this->p)));
      
      // {{{ blockMix
      $blockMix = function ($Offset) use (&$X, $blockSize) {
        // Get the last chunk from the offseted block
        $T = array_slice ($X, $Offset + $blockSize - 16, 16);
        
        for ($i = 0; $i < $blockSize / 16; $i++) {
          for ($j = 0; $j < 16; $j++)
            $T [$j] ^= $X [$Offset + ($i * 16) + $j];
          
          $T = $this::salsa20a ($T, 8);
          $Y [$i] = $T;
        }
        
        foreach ($Y as $k=>$V) {
          $o =  (floor ($k / 2) + ($k % 2 == 0 ? 0 : ceil (count ($Y) / 2))) * 16;
          
          foreach ($V as $i=>$v)
            $X [$Offset + $o + $i] = $v;
        }
      };
      // }}} blockMix
      
      // {{{ romix
      for ($o = 0; $o < $this->p; $o++) {
        $Offset = $o * $blockSize;
        $V = array ();
        
        for ($i = 0; $i < $this->N; $i++) {
          $V [$i] = array_slice ($X, $Offset, $blockSize);
          $blockMix ($Offset);
        }
        
        for ($i = 0; $i < $this->N; $i++) {
          $j = $X [$Offset + $blockSize - 16] & ($this->N - 1);
          
          for ($k = 0; $k < $blockSize; $k++)
            $X [$Offset + $k] ^= $V [$j][$k];
          
          $blockMix ($Offset);
        }
      }
      // }}} romix
      
      // Generate salt
      array_unshift ($X, str_repeat ('V', $this->p * $blockSize));
      $Salt = call_user_func_array ('pack', $X);
      
      // Generate result
      return $this->pbkdf2 ($Input, $Salt, 1, $this->dkLen);
    }
    // }}}
    
    // {{{ salsa20a
    /**
     * Apply Salsa20-Cipher on an 16-element array of 32-Bit Intergers
     * 
     * @param array $X
     * @param int $Rounds (optional)
     * 
     * @access private
     * @return array
     **/
    private static function salsa20a (array $X, $Rounds = 20) {
      // Salsa20-Groups
      static $Groups = array (
        array ( 0,  4,  8, 12),
        array ( 5,  9, 13,  1),
        array (10, 14,  2,  6),
        array (15,  3,  7, 11),
        
        array ( 0,  1,  2,  3),
        array ( 5,  6,  7,  4),
        array (10, 11,  8,  9),
        array (15, 12, 13, 14),
      );
      
      // Shift+Rotate
      static $rotl = null;
      
      if ($rotl === null)
        $rotl = function ($a, $b) {
          $a = $a & 0xFFFFFFFF;
          return ((($a << $b) | ($a >> (32 - $b))) & 0xFFFFFFFF);
        };
      
      // Generate output
      $R = $X;
      
      for ($r = 0; $r < 8; $r += 2) {
        foreach ($Groups as $G) {
          $X [$G [1]] ^= $rotl ($X [$G [0]] + $X [$G [3]],  7);
          $X [$G [2]] ^= $rotl ($X [$G [1]] + $X [$G [0]],  9);
          $X [$G [3]] ^= $rotl ($X [$G [2]] + $X [$G [1]], 13);
          $X [$G [0]] ^= $rotl ($X [$G [3]] + $X [$G [2]], 18);
        }
      }
      
      for ($k = 0; $k < 16; $k++)
        $R [$k] = ($R [$k] + $X [$k]) & 0xFFFFFFFF;
      
      return $R;
    }
    // }}}
    
    // {{{ nosalt
    /**
     * Generate hash without explicit salt
     * 
     * @param string $Input
     * @param int $sLen (optional) Use first sLen bytes of input as salt
     * 
     * @access public
     * @return string
     **/
    public function nosalt ($Input, $sLen = null) {
      if ($sLen !== null)
        return $this ($Input, substr ($Input, 0, $sLen));
      
      return $this ($Input, $Input);
    }
    // }}}
    
    // {{{ pbkdf2
    /**
     * Generate PBKDF2-Output
     * 
     * @param string $Input
     * @param string $Salt
     * @param int $Iterations
     * @param int $Size
     * 
     * @access private
     * @return string
     **/
    private function pbkdf2 ($Input, $Salt, $Iterations, $Size) {
      return hash_pbkdf2 ($this->PRNG, $Input, $Salt, $Iterations, $Size, true);
    }
    // }}}
  }

?>