# syntax=docker/dockerfile:1.3
FROM corpusops/ubuntu-bare:20.04
WORKDIR /tmp/install
ARG DEV_DEPENDENCIES_PATTERN='^#\s*dev dependencies' \
    PY_VER=3.8 \
    USER_NAME=app USER_UID=1000 USER_GROUP= USER_GID= \
    USER_HOME=/w
ARG PIP_SRC=$USER_HOME/lib
ENV USER_NAME=$USER_NAME USER_GROUP=${USER_GROUP:-$USER_NAME} USER_UID=$USER_UID USER_GID=${USER_GID:-${USER_UID}} USER_HOME=$USER_HOME PY_VER=${PY_VER:-} PIP_SRC=$PIP_SRC

# system dependendencies (pkgs, users, etc)
ADD apt*.txt ./
RUN set -e \
  && if !( getent group  $USER_NAME 2>/dev/null);then groupadd -g $USER_GID $USER_NAME;fi \
  && if !( getent passwd $USER_NAME 2>/dev/null);then \
    useradd -s /bin/bash -d $USER_HOME -m -u $USER_UID -g $USER_UID $USER_NAME;fi \
  && sed -i -re "s/(python-?)[0-9]\.[0-9]+/\1$PY_VER/g" apt.txt \
  && apt update && apt install -y $(egrep -v "^#" apt.txt) \
  && mkdir -pv "$PIP_SRC" && chown $USER_NAME "$PIP_SRC" \
  && printf "$USER_NAME ALL=(ALL) NOPASSWD:ALL\n">/etc/sudoers.d/app \
  && : end

# install python app
WORKDIR $USER_HOME
# See https://github.com/pypa/setuptools/issues/3301
# ARG PIP_REQ=>=22 SETUPTOOLS_REQ=<60 \
ARG PIP_REQ=>=22 SETUPTOOLS_REQ>=60 \
    REQUIREMENTS=requirements/requirements.txt requirements/requirements-dev.txt
ENV REQUIREMENTS=$REQUIREMENTS PIP_REQ=$PIP_REQ SETUPTOOLS_REQ=$SETUPTOOLS_REQ
ADD --chown=app:app lib/ lib/
ADD --chown=app:app src/ src/
ADD --chown=app:app *.py *txt *md *in ./
RUN mkdir requirements
ADD --chown=app:app requirements/requirement* requirements/
RUN bash -c 'set -e \
  && for i in / /usr /usr/local;do \
  ln -fsv $(which python${PY_VER}) $i/bin/python;done \
  && python <(curl https://bootstrap.pypa.io/get-pip.py) \
  && pip install --upgrade pip${PIP_REQ} setuptools${SETUPTOOLS_REQ} \
  && SETUPTOOLS_USE_DISTUTILS=stdlib python -m pip install --no-cache -r <( cat $REQUIREMENTS ) \
  && chown -Rf $USER_NAME .'

# add and install node
ARG GITHUB_PAT="NTA2N2MxYTQzNDgzOGRkYzZkZTczZTZlNjljZTFkNGEzNWZjMWMxOAo="
ARG NVM_RELEASE="latest"
ARG NVMURI="https://api.github.com/repos/nvm-sh/nvm/releases"
ARG NVMDLURI="https://raw.githubusercontent.com/nvm-sh/nvm"
ENV PATH=$USER_HOME/node_modules/.bin:$USER_HOME/bin:$PATH
RUN bash -lc "set -ex \
  && if !( echo $NVM_RELEASE|egrep -q ^latest$ );then NVMURI=\"$NVMURI/tags\";fi \
  && curl -sH \"Authorization: token $(echo $GITHUB_PAT|base64 -d)\" \
        \"$NVMURI/$NVM_RELEASE\"|grep tag_name|cut -d '\"' -f 4 > /tmp/install/node_version \
  && curl -sL $NVMDLURI/\$(cat /tmp/install/node_version)/install.sh -o /bin/install_nvm.sh \
  && chmod +x /bin/install_nvm.sh \
  && gosu $USER_NAME install_nvm.sh"
ADD --chown=app:app .nvmrc ./
RUN gosu $USER_NAME bash -ic '. .bashrc && nvm install $(cat .nvmrc)'
# add and install node app
ARG PACKAGEJSON_LOCATION=requirements
ARG NPM_TARGET=ci
ENV PACKAGEJSON_LOCATION=$PACKAGEJSON_LOCATION
ADD --chown=app:app $PACKAGEJSON_LOCATION/*json ${PACKAGEJSON_LOCATION}/
ADD --chown=app:app package*json ./
RUN gosu $USER_NAME bash -ic 'set -e \
    && nvm use \
    && if !( grep -q '"name"' package-lock.json );then NPM_TARGET=install;fi \
    && npm $NPM_TARGET'

# final cleanup
RUN \
  set -ex \
  && sed -i -re "s/(python-?)[0-9]\.[0-9]+/\1$PY_VER/g" apt.txt \
  && apt install $(dpkg -l|awk '{print $2}'|grep -v -- -dev|egrep python.?-) \
  && if $(egrep -q "${DEV_DEPENDENCIES_PATTERN}" apt.txt);then \
    apt-get remove --auto-remove --purge \
  $(sed "1,/${DEV_DEPENDENCIES_PATTERN}/ d" apt.txt|grep -v '^#'|tr "\n" " ");\
  fi \
  && rm -rf /var/lib/apt/lists/* /tmp/install
# run settings
ADD --chown=app:app .git/ .git/
ADD --chown=app:app bin/  bin/
ENTRYPOINT ["docker-entrypoint.sh"]
