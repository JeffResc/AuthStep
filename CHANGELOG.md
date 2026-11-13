# Changelog

## [0.1.5](https://github.com/JeffResc/AuthStep/compare/authstep-v0.1.4...authstep-v0.1.5) (2026-11-13)


### Bug Fixes

* **admin:** cancel pending SCEP enrolments when revoking all certificates ([b9a7d6e](https://github.com/JeffResc/AuthStep/commit/b9a7d6e6b5dc392f159247396afe9558a797e7b1))
* **admin:** cancel pending SCEP enrolments when revoking all certificates ([398e2b3](https://github.com/JeffResc/AuthStep/commit/398e2b30e74f5fb304156030cd022cd99f447936))
* **audit:** ignore non-IP forwarded hops and document narrow trusted proxies ([1be0d98](https://github.com/JeffResc/AuthStep/commit/1be0d9857bf844756cfe0d7df818538c4b9f19e6))
* **audit:** ignore non-IP forwarded hops and document narrow trusted proxies ([003a256](https://github.com/JeffResc/AuthStep/commit/003a256328cee9d586574fa260c75f2cae9f9054))
* **deps:** update Go to 1.26.11 to fix GO-2026-6859 in net/http ([3641da2](https://github.com/JeffResc/AuthStep/commit/3641da28ec1911d563263f276b85a71eef371544))
* **deps:** update Go to 1.26.11 to fix GO-2026-6859 in net/http ([b49822e](https://github.com/JeffResc/AuthStep/commit/b49822e8070669e725099300025cb0c9215f2673))
* **scep:** deny same-transaction challenge replay once the enrolment is no longer issuing ([7031d27](https://github.com/JeffResc/AuthStep/commit/7031d278b0206edb4aeff894eb82b81f54c6c75d))
* **scep:** deny same-transaction challenge replay once the enrolment is no longer issuing ([06cc10e](https://github.com/JeffResc/AuthStep/commit/06cc10ec93977546a4352b32585bc574adc1b754))


### Miscellaneous

* **deps:** update dependency helm to v4.3.2 ([c68ad4a](https://github.com/JeffResc/AuthStep/commit/c68ad4adc0fea50af5df2827c0fa0028421f74b4))
* **deps:** update dependency helm to v4.3.2 ([ad8da9b](https://github.com/JeffResc/AuthStep/commit/ad8da9b0a2cbf060034c58f8fa4be6982407e072))
* **deps:** update go module directive to v1.27.4 ([993b6a4](https://github.com/JeffResc/AuthStep/commit/993b6a405bf667bbc5c4ea5f85a216dc12d1a4be))
* **deps:** update go module directive to v1.27.4 ([7167d40](https://github.com/JeffResc/AuthStep/commit/7167d40baae8e74f65155443d569e95bbeba4196))
* **deps:** update golang docker tag to v1.27.4 ([0a1d2d3](https://github.com/JeffResc/AuthStep/commit/0a1d2d38c979c52a1e1c330c79cceed7e846a275))
* **deps:** update golang docker tag to v1.27.4 ([51e6ee0](https://github.com/JeffResc/AuthStep/commit/51e6ee09eed718027e5cb4fcbd668a59ea346e15))

## [0.1.4](https://github.com/JeffResc/AuthStep/compare/authstep-v0.1.3...authstep-v0.1.4) (2026-11-10)


### Bug Fixes

* **web:** download new certificate files as normal files on iOS ([e6d9178](https://github.com/JeffResc/AuthStep/commit/e6d91781c2ad9371f08424ac6f9036178b125cbb))
* **web:** serve new certificate downloads as octet-stream so iOS saves them to Files instead of opening them as profiles ([bfa8ac7](https://github.com/JeffResc/AuthStep/commit/bfa8ac74d41061f007ba77961f2045885958324c))

## [0.1.3](https://github.com/JeffResc/AuthStep/compare/authstep-v0.1.2...authstep-v0.1.3) (2026-11-10)


### Features

* **auth:** make the email_verified check optional with oidc.requireEmailVerified ([50055fb](https://github.com/JeffResc/AuthStep/commit/50055fbf5dc34bbc2f8cecd74f5f2a4da80b9837))
* **auth:** make the email_verified check optional with oidc.requireEmailVerified ([f30e382](https://github.com/JeffResc/AuthStep/commit/f30e38237879ddb4fab1d1084639a1d2c6e67565))


### Bug Fixes

* **deps:** update module golang.org/x/oauth2 to v0.38.0 ([ca70995](https://github.com/JeffResc/AuthStep/commit/ca709952e4341a121368d7165762ba7679c9f137))
* **deps:** update module golang.org/x/oauth2 to v0.38.0 ([20daa00](https://github.com/JeffResc/AuthStep/commit/20daa003420be6773458806820aa0209e3dc3d13))


### Miscellaneous

* **deps:** update azure/setup-helm digest to 2f5e7bc ([85a554c](https://github.com/JeffResc/AuthStep/commit/85a554cc79e0d788dc4863c9a9c6f06d81ebe597))
* **deps:** update azure/setup-helm digest to 2f5e7bc ([a13a814](https://github.com/JeffResc/AuthStep/commit/a13a81400edfb3e95595b3456d31d787eaac1a71))

## [0.1.2](https://github.com/JeffResc/AuthStep/compare/authstep-v0.1.1...authstep-v0.1.2) (2026-11-08)


### Features

* **helm:** read the OIDC client ID from an existing Secret via oidc.clientIDSecret ([0fd9cfd](https://github.com/JeffResc/AuthStep/commit/0fd9cfde999fe71cb87db89b6a798868ea3e51ed))

## [0.1.1](https://github.com/JeffResc/AuthStep/compare/authstep-v0.1.0...authstep-v0.1.1) (2026-11-08)


### Features

* **smtp:** allow plaintext SMTP to relays without STARTTLS ([142c49f](https://github.com/JeffResc/AuthStep/commit/142c49fef5593838a9622f6bf6b742759e00ce9b))
* **smtp:** allow plaintext SMTP to relays without STARTTLS via the smtp.allowPlaintext helm value ([ba96b64](https://github.com/JeffResc/AuthStep/commit/ba96b64736a78212ce117ac9f9cf73b0aba07897))


### Bug Fixes

* **ci:** tag release container images with the version number ([ff653c2](https://github.com/JeffResc/AuthStep/commit/ff653c2ce42fa47f68346a5747a2e51a7fc35b00))
* **ci:** tag release container images with the version number ([f275baf](https://github.com/JeffResc/AuthStep/commit/f275baffaa3431399ee20f4f0cdd88be5e52f3dc))


### Miscellaneous

* **release:** remove the release-as 0.1.0 pin from the release-please config ([b991446](https://github.com/JeffResc/AuthStep/commit/b991446ccfdb62f789fe68bf5169f0c091c60a1c))

## 0.1.0 (2026-11-08)


### Features

* add Apple TV enrolment through one-time links, cancellation of pending Apple requests, a .pfx download and OS-based device name examples ([eedd2cd](https://github.com/JeffResc/AuthStep/commit/eedd2cd8dce2a2dd9709ccbba451d13c1ed584ee))
* add AuthStep self-service client certificate service backed by step-ca with Helm chart and docs ([7b071e8](https://github.com/JeffResc/AuthStep/commit/7b071e851985c896ccfd479abdaeaee81ab04d85))
* show pending Apple enrolments, return to the original page after sign-in, trust the AuthStep root for SMTP and add a k3d demo with optional Cloudflare tunnels ([2002d5e](https://github.com/JeffResc/AuthStep/commit/2002d5e116246938eac06ffeeadfc4021f2f6c7c))


### Bug Fixes

* **deps:** update module go.step.sm/crypto to v0.92.0 ([3fd035a](https://github.com/JeffResc/AuthStep/commit/3fd035a0491784fc9d3c4eb20f522b3349cd2708))
* **deps:** update module go.step.sm/crypto to v0.92.0 ([6378ba8](https://github.com/JeffResc/AuthStep/commit/6378ba88033c036528ad9490cc79e6229f1e3b7c))
* **deps:** update module modernc.org/sqlite to v1.62.0 ([d7e1de4](https://github.com/JeffResc/AuthStep/commit/d7e1de479fc1095cf8050fa141e80accb884390c))
* **deps:** update module modernc.org/sqlite to v1.62.0 ([203ebac](https://github.com/JeffResc/AuthStep/commit/203ebacb023de541e68a65ec798ec753e3f7034c))
* **deps:** use Serialize for JWTs now that go.step.sm/crypto v0.92.0 wraps go-jose v4 ([4005449](https://github.com/JeffResc/AuthStep/commit/4005449317d241809e4ea34830b0aabfd413298b))


### Miscellaneous

* **deps:** update codecov/codecov-action digest to 303a32d ([0ee4eb5](https://github.com/JeffResc/AuthStep/commit/0ee4eb5efbbef19528bac241540e3705dc390f0d))
* **deps:** update codecov/codecov-action digest to 303a32d ([cefc106](https://github.com/JeffResc/AuthStep/commit/cefc1060f2d31334f67872ab67f23bf3e70468d5))
* **deps:** update docker/build-push-action digest to c3c9e26 ([1e87bc9](https://github.com/JeffResc/AuthStep/commit/1e87bc9cfda13d84eed7f2f261b8b5b870e77f31))
* **deps:** update docker/build-push-action digest to c3c9e26 ([8d646db](https://github.com/JeffResc/AuthStep/commit/8d646db8e91c887205e48a209977e9846ff8b81a))
* **deps:** update docker/login-action digest to 8aa5831 ([a47721b](https://github.com/JeffResc/AuthStep/commit/a47721b878571ebb5cf6381ddb225af755744a5f))
* **deps:** update docker/login-action digest to 8aa5831 ([4ee49a8](https://github.com/JeffResc/AuthStep/commit/4ee49a871d396701d91f36ff97a442f012f745e9))
* **deps:** update docker/setup-buildx-action digest to f87e599 ([54a4618](https://github.com/JeffResc/AuthStep/commit/54a4618fb7df9c6117601806e7a9e11e35822c3f))
* **deps:** update docker/setup-buildx-action digest to f87e599 ([ba990d8](https://github.com/JeffResc/AuthStep/commit/ba990d82fa8990aa6464cb47784c58df56e34ee6))
* **deps:** update docker/setup-qemu-action digest to 9901266 ([70a2ed5](https://github.com/JeffResc/AuthStep/commit/70a2ed5b989d8808789787b60db10cb1f1bc8e67))
* **deps:** update docker/setup-qemu-action digest to 9901266 ([65742c8](https://github.com/JeffResc/AuthStep/commit/65742c8e83a89e5d72e63e7d5af91ab8484536df))
* **deps:** update golang docker tag to v1.27.3 ([9f3c604](https://github.com/JeffResc/AuthStep/commit/9f3c6044157c08f1167b5318517d00d32429f424))
* **deps:** update golang docker tag to v1.27.3 ([0c76661](https://github.com/JeffResc/AuthStep/commit/0c766615124ce8455899283b12d7e7b9976c7510))
* **deps:** update litestream/litestream docker tag to v0.5.18 ([c5c3d63](https://github.com/JeffResc/AuthStep/commit/c5c3d63f2790a89d03f4df9e16ed23ad7567fc43))
* **deps:** update litestream/litestream docker tag to v0.5.18 ([25e872a](https://github.com/JeffResc/AuthStep/commit/25e872af40db9db22f2543eef9d81e1fd46f0c17))
* merge main into the go.step.sm/crypto update ([efa0a40](https://github.com/JeffResc/AuthStep/commit/efa0a40cb7d471dc59a0b0ac645171b71131c1aa))
