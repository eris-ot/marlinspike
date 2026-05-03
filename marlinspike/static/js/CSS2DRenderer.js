// CSS2DRenderer — extracted from riverflow-3d.html prototype
// ES6 class syntax required for Three.js r128 compatibility

THREE.CSS2DObject = class extends THREE.Object3D {
  constructor(element) {
    super();
    this.element = element;
    this.element.style.position = 'absolute';
    this.element.style.userSelect = 'none';
    this.element.setAttribute('draggable', false);
    this.addEventListener('removed', function() {
      this.traverse(function(object) {
        if (object.element instanceof Element && object.element.parentNode !== null) {
          object.element.parentNode.removeChild(object.element);
        }
      });
    });
  }
  copy(source, recursive) {
    super.copy(source, recursive);
    this.element = source.element.cloneNode(true);
    return this;
  }
};

THREE.CSS2DRenderer = function() {
  var _this = this;
  var _width, _height;
  var _widthHalf, _heightHalf;
  var vector = new THREE.Vector3();
  var viewMatrix = new THREE.Matrix4();
  var viewProjectionMatrix = new THREE.Matrix4();
  var cache = { objects: new WeakMap() };

  var domElement = document.createElement('div');
  domElement.style.overflow = 'hidden';
  this.domElement = domElement;

  this.getSize = function() { return { width: _width, height: _height }; };

  this.setSize = function(width, height) {
    _width = width; _height = height;
    _widthHalf = _width / 2; _heightHalf = _height / 2;
    domElement.style.width = width + 'px';
    domElement.style.height = height + 'px';
  };

  var renderObject = function(object, scene, camera) {
    if (object instanceof THREE.CSS2DObject) {
      object.onBeforeRender(_this, scene, camera);
      vector.setFromMatrixPosition(object.matrixWorld);
      vector.applyMatrix4(viewProjectionMatrix);
      var element = object.element;
      var style = 'translate(-50%,-50%) translate(' +
        (vector.x * _widthHalf + _widthHalf) + 'px,' +
        (-vector.y * _heightHalf + _heightHalf) + 'px)';
      element.style.WebkitTransform = style;
      element.style.MozTransform = style;
      element.style.transform = style;
      element.style.display = (object.visible && vector.z >= -1 && vector.z <= 1) ? '' : 'none';
      var objectData = { distanceToCameraSquared: getDistanceToSquared(camera, object) };
      cache.objects.set(object, objectData);
      if (element.parentNode !== domElement) domElement.appendChild(element);
      object.onAfterRender(_this, scene, camera);
    }
    for (var i = 0, l = object.children.length; i < l; i++) {
      renderObject(object.children[i], scene, camera);
    }
  };

  var getDistanceToSquared = function() {
    var a = new THREE.Vector3();
    var b = new THREE.Vector3();
    return function(object1, object2) {
      a.setFromMatrixPosition(object1.matrixWorld);
      b.setFromMatrixPosition(object2.matrixWorld);
      return a.distanceToSquared(b);
    };
  }();

  this.render = function(scene, camera) {
    if (scene.autoUpdate === true) scene.updateMatrixWorld();
    if (camera.parent === null) camera.updateMatrixWorld();
    viewMatrix.copy(camera.matrixWorldInverse);
    viewProjectionMatrix.multiplyMatrices(camera.projectionMatrix, viewMatrix);
    renderObject(scene, scene, camera);
  };
};
