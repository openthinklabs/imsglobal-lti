<?php

/**
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; under version 2
 * of the License (non-upgradable).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (c) 2022 (original work) Open Assessment Technologies SA.
 */

declare(strict_types=1);

namespace IMSGlobal\LTI\OAuth;

/**
 * A class for implementing a Signature Method
 * See section 9 ("Signing Requests") in the spec
 */
abstract class OAuthSignatureMethod
{
    /**
     * Needs to return the name of the Signature Method (ie HMAC-SHA1)
     *
     * @return string
     */
    abstract public function get_name();

    /**
     * Build up the signature
     * NOTE: The output of this function MUST NOT be urlencoded.
     * the encoding is handled in OAuthRequest when the final
     * request is serialized
     *
     * @param OAuthRequest $request
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     *
     * @return string
     */
    abstract public function build_signature($request, $consumer, $token);

    /**
     * Verifies that a given signature is correct
     *
     * @param OAuthRequest $request
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     * @param string $signature
     *
     * @return bool
     */
    public function check_signature($request, $consumer, $token, $signature)
    {
        $built = $this->build_signature($request, $consumer, $token);
        $builtLength = strlen($built);
        $signatureLength = strlen($signature);

        // Check for zero length, although unlikely here
        if ($builtLength === 0 || $signatureLength === 0 || $builtLength !== $signatureLength) {
            return false;
        }

        // Avoid a timing leak with a (hopefully) time insensitive compare
        $result = 0;

        for ($i = 0; $i < $signatureLength; ++$i) {
            $result |= ord($built[$i]) ^ ord($signature[$i]);
        }

        return $result === 0;
    }
}
