// OrbitControls — minimal implementation extracted from riverflow-3d.html prototype
// Compatible with Three.js r128

THREE.OrbitControls = function(camera, domElement) {
  this.camera = camera;
  this.domElement = domElement;
  this.target = new THREE.Vector3();
  this.enableDamping = true;
  this.dampingFactor = 0.08;
  this.rotateSpeed = 0.6;
  this.zoomSpeed = 1.2;
  this.panSpeed = 0.8;
  this.minDistance = 5;
  this.maxDistance = 80;
  this.minPolarAngle = 0.1;
  this.maxPolarAngle = Math.PI * 0.48;
  this.enabled = true;
  this.autoRotate = false;
  this.autoRotateSpeed = 0.3;

  var scope = this;
  var spherical = new THREE.Spherical();
  var sphericalDelta = new THREE.Spherical();
  var panOffset = new THREE.Vector3();
  var scale = 1;
  var rotateStart = new THREE.Vector2();
  var panStart = new THREE.Vector2();
  var state = -1; // NONE
  var EPS = 0.000001;

  this.update = function() {
    var offset = new THREE.Vector3();
    var quat = new THREE.Quaternion().setFromUnitVectors(camera.up, new THREE.Vector3(0, 1, 0));
    var quatInverse = quat.clone().invert();
    var lastPosition = new THREE.Vector3();

    return function update() {
      // Auto-rotation when idle
      if (scope.autoRotate && state === -1) {
        sphericalDelta.theta -= 2 * Math.PI / 60 / 60 * scope.autoRotateSpeed;
      }

      var position = scope.camera.position;
      offset.copy(position).sub(scope.target);
      offset.applyQuaternion(quat);
      spherical.setFromVector3(offset);
      spherical.theta += sphericalDelta.theta;
      spherical.phi += sphericalDelta.phi;
      spherical.phi = Math.max(scope.minPolarAngle, Math.min(scope.maxPolarAngle, spherical.phi));
      spherical.makeSafe();
      spherical.radius *= scale;
      spherical.radius = Math.max(scope.minDistance, Math.min(scope.maxDistance, spherical.radius));
      scope.target.add(panOffset);
      offset.setFromSpherical(spherical);
      offset.applyQuaternion(quatInverse);
      position.copy(scope.target).add(offset);
      scope.camera.lookAt(scope.target);

      if (scope.enableDamping) {
        sphericalDelta.theta *= (1 - scope.dampingFactor);
        sphericalDelta.phi *= (1 - scope.dampingFactor);
        panOffset.multiplyScalar(1 - scope.dampingFactor);
      } else {
        sphericalDelta.set(0, 0, 0);
        panOffset.set(0, 0, 0);
      }
      scale = 1;
      if (lastPosition.distanceToSquared(scope.camera.position) > EPS) {
        lastPosition.copy(scope.camera.position);
        return true;
      }
      return false;
    };
  }();

  function panLeft(distance, objectMatrix) {
    var v = new THREE.Vector3();
    v.setFromMatrixColumn(objectMatrix, 0);
    v.multiplyScalar(-distance);
    panOffset.add(v);
  }
  function panUp(distance, objectMatrix) {
    var v = new THREE.Vector3();
    v.setFromMatrixColumn(objectMatrix, 1);
    v.multiplyScalar(distance);
    panOffset.add(v);
  }
  function pan(deltaX, deltaY) {
    var element = scope.domElement;
    var offset = new THREE.Vector3();
    offset.copy(scope.camera.position).sub(scope.target);
    var targetDistance = offset.length();
    targetDistance *= Math.tan((scope.camera.fov / 2) * Math.PI / 180.0);
    panLeft(2 * deltaX * targetDistance / element.clientHeight, scope.camera.matrix);
    panUp(2 * deltaY * targetDistance / element.clientHeight, scope.camera.matrix);
  }

  function onMouseDown(event) {
    if (!scope.enabled) return;
    event.preventDefault();
    if (event.button === 0) {
      state = 0; // ROTATE
      rotateStart.set(event.clientX, event.clientY);
    } else if (event.button === 2) {
      state = 1; // PAN
      panStart.set(event.clientX, event.clientY);
    }
    document.addEventListener('mousemove', onMouseMove, false);
    document.addEventListener('mouseup', onMouseUp, false);
  }
  function onMouseMove(event) {
    if (!scope.enabled) return;
    if (state === 0) {
      var rotateDelta = new THREE.Vector2(event.clientX - rotateStart.x, event.clientY - rotateStart.y);
      sphericalDelta.theta -= 2 * Math.PI * rotateDelta.x / domElement.clientHeight * scope.rotateSpeed;
      sphericalDelta.phi -= 2 * Math.PI * rotateDelta.y / domElement.clientHeight * scope.rotateSpeed;
      rotateStart.set(event.clientX, event.clientY);
    } else if (state === 1) {
      var panDelta = new THREE.Vector2(event.clientX - panStart.x, event.clientY - panStart.y);
      pan(panDelta.x, panDelta.y);
      panStart.set(event.clientX, event.clientY);
    }
  }
  function onMouseUp() {
    state = -1;
    document.removeEventListener('mousemove', onMouseMove, false);
    document.removeEventListener('mouseup', onMouseUp, false);
  }
  function onMouseWheel(event) {
    if (!scope.enabled) return;
    event.preventDefault();
    if (event.deltaY < 0) scale /= Math.pow(0.95, scope.zoomSpeed);
    else if (event.deltaY > 0) scale *= Math.pow(0.95, scope.zoomSpeed);
  }
  function onContextMenu(event) { event.preventDefault(); }

  domElement.addEventListener('mousedown', onMouseDown, false);
  domElement.addEventListener('wheel', onMouseWheel, { passive: false });
  domElement.addEventListener('contextmenu', onContextMenu, false);

  this.dispose = function() {
    domElement.removeEventListener('mousedown', onMouseDown);
    domElement.removeEventListener('wheel', onMouseWheel);
    domElement.removeEventListener('contextmenu', onContextMenu);
  };

  this.update();
};
